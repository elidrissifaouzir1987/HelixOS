#![forbid(unsafe_code)]
//! Assemblage du service noyau HelixOS (bootstrap MVP-0) : configuration, chargement de la PKI
//! depuis le disque, et exécution CONCURRENTE des deux serveurs (mTLS pour les appelants +
//! micro-page HTTPS d'approbation) sur UN SEUL [`SharedKernel`] partagé.
//!
//! Propriété centrale prouvée par l'assemblage : les deux serveurs opèrent sur le MÊME
//! `Arc<Mutex<Kernel>>`. Un plan créé par un appelant via la frontière mTLS est donc
//! immédiatement visible et approuvable sur la page HTTPS (même carte, même `apply`) — pas deux
//! noyaux indépendants aux vues divergentes.
//!
//! Ce module (dans la lib, pas dans `main.rs`) porte toute la logique testable de l'assemblage :
//! `main.rs` n'en est qu'un mince pilote (parse des args réels + installation du Ctrl-C). La
//! génération de certificats n'a PAS sa place ici — le runtime CHARGE des certs provisionnés hors
//! bande par `helixos-provision` (le runtime n'embarque donc jamais `rcgen`).

use crate::approval::server::{build_router, serve_https};
use crate::mtls::{build_server_config, serve_mtls};
use crate::pipeline::{Kernel, SharedKernel};
use crate::scope::ScopeLease;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Adresses d'écoute par défaut (voir énoncé bootstrap MVP-0).
pub const DEFAULT_MTLS_ADDR: &str = "127.0.0.1:8443";
pub const DEFAULT_APPROVAL_ADDR: &str = "127.0.0.1:8600";
pub const DEFAULT_APPROVAL_ORIGIN: &str = "https://localhost:8600";
pub const DEFAULT_TASK_ID: &str = "local";

/// Configuration du service noyau, résolue depuis les arguments/environnement.
#[derive(Debug, Clone)]
pub struct Config {
    /// État persistant du noyau (plans consommés, audit).
    pub state_dir: PathBuf,
    /// Racine(s) du bail de portée — le vault. Contrôle PRIMAIRE : rien n'est planifiable hors de là.
    pub vault_roots: Vec<PathBuf>,
    /// Répertoire de la PKI produite par `helixos-provision`.
    pub cert_dir: PathBuf,
    /// Adresse d'écoute du serveur mTLS (appelants).
    pub mtls_addr: String,
    /// Adresse d'écoute de la micro-page HTTPS d'approbation.
    pub approval_addr: String,
    /// Origine d'approbation (URL affichée/attendue par le navigateur). Conservée pour le
    /// diagnostic au démarrage ; le SAN du certificat d'approbation est fixé à la génération.
    pub approval_origin: String,
    /// `task_id` du bail par-tâche.
    pub task_id: String,
}

impl Config {
    /// Construit le [`ScopeLease`] correspondant (bail par-tâche sur les racines du vault).
    pub fn lease(&self) -> ScopeLease {
        ScopeLease { task_id: self.task_id.clone(), roots: self.vault_roots.clone() }
    }
}

const USAGE: &str = "\
helixos-kernel — service noyau HelixOS (serveur mTLS + page d'approbation, noyau partagé)

USAGE:
    helixos-kernel --state-dir <DIR> --vault-root <DIR> --cert-dir <DIR> [OPTIONS]

OPTIONS REQUISES:
    --state-dir <DIR>        État persistant du noyau (plans consommés, audit).
    --vault-root <DIR>       Racine du bail de portée (le vault). Répétable pour plusieurs racines.
    --cert-dir <DIR>         Répertoire de la PKI (généré par helixos-provision).

OPTIONS:
    --mtls-addr <ADDR>       Adresse du serveur mTLS (défaut: 127.0.0.1:8443).
    --approval-addr <ADDR>   Adresse de la page d'approbation (défaut: 127.0.0.1:8600).
    --approval-origin <URL>  Origine d'approbation (défaut: https://localhost:8600).
    --task-id <ID>           task_id du bail par-tâche (défaut: local).
    -h, --help               Affiche cette aide.

Les valeurs peuvent aussi venir de l'environnement (HELIXOS_STATE_DIR, HELIXOS_VAULT_ROOT,
HELIXOS_CERT_DIR, HELIXOS_MTLS_ADDR, HELIXOS_APPROVAL_ADDR, HELIXOS_APPROVAL_ORIGIN,
HELIXOS_TASK_ID) ; un argument de ligne de commande a toujours la priorité.
";

/// Résultat du parsing : soit une config, soit une demande d'aide (`--help`).
#[derive(Debug)]
pub enum ParseOutcome {
    Run(Config),
    Help,
}

/// Parse args + environnement (l'argument gagne sur l'env). Aucune dépendance lourde : jeu
/// d'options fixe et petit. `--vault-root` est répétable (plusieurs racines de bail). Renvoie
/// `Err` lisible sur option inconnue, valeur manquante, ou option requise absente.
///
/// `env` est injecté (plutôt que `std::env::var` en dur) pour rester testable sans muter
/// l'environnement du processus de test.
pub fn parse_config<A, E>(args: A, env: E) -> Result<ParseOutcome, String>
where
    A: IntoIterator<Item = String>,
    E: Fn(&str) -> Option<String>,
{
    let mut state_dir: Option<PathBuf> = None;
    let mut vault_roots: Vec<PathBuf> = Vec::new();
    let mut cert_dir: Option<PathBuf> = None;
    let mut mtls_addr: Option<String> = None;
    let mut approval_addr: Option<String> = None;
    let mut approval_origin: Option<String> = None;
    let mut task_id: Option<String> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--state-dir" => state_dir = Some(PathBuf::from(next_value(&mut it, "--state-dir")?)),
            "--vault-root" => vault_roots.push(PathBuf::from(next_value(&mut it, "--vault-root")?)),
            "--cert-dir" => cert_dir = Some(PathBuf::from(next_value(&mut it, "--cert-dir")?)),
            "--mtls-addr" => mtls_addr = Some(next_value(&mut it, "--mtls-addr")?),
            "--approval-addr" => approval_addr = Some(next_value(&mut it, "--approval-addr")?),
            "--approval-origin" => approval_origin = Some(next_value(&mut it, "--approval-origin")?),
            "--task-id" => task_id = Some(next_value(&mut it, "--task-id")?),
            other => return Err(format!("option inconnue: {other}")),
        }
    }

    // Repli sur l'environnement pour ce qui n'a pas été fourni en argument (l'argument gagne).
    let state_dir = state_dir
        .or_else(|| env("HELIXOS_STATE_DIR").map(PathBuf::from))
        .ok_or("--state-dir <DIR> est requis (ou HELIXOS_STATE_DIR)")?;
    if vault_roots.is_empty() {
        if let Some(v) = env("HELIXOS_VAULT_ROOT") {
            vault_roots.push(PathBuf::from(v));
        }
    }
    if vault_roots.is_empty() {
        return Err("--vault-root <DIR> est requis (ou HELIXOS_VAULT_ROOT)".into());
    }
    let cert_dir = cert_dir
        .or_else(|| env("HELIXOS_CERT_DIR").map(PathBuf::from))
        .ok_or("--cert-dir <DIR> est requis (ou HELIXOS_CERT_DIR)")?;

    let mtls_addr = mtls_addr
        .or_else(|| env("HELIXOS_MTLS_ADDR"))
        .unwrap_or_else(|| DEFAULT_MTLS_ADDR.to_string());
    let approval_addr = approval_addr
        .or_else(|| env("HELIXOS_APPROVAL_ADDR"))
        .unwrap_or_else(|| DEFAULT_APPROVAL_ADDR.to_string());
    let approval_origin = approval_origin
        .or_else(|| env("HELIXOS_APPROVAL_ORIGIN"))
        .unwrap_or_else(|| DEFAULT_APPROVAL_ORIGIN.to_string());
    let task_id = task_id
        .or_else(|| env("HELIXOS_TASK_ID"))
        .unwrap_or_else(|| DEFAULT_TASK_ID.to_string());

    Ok(ParseOutcome::Run(Config {
        state_dir,
        vault_roots,
        cert_dir,
        mtls_addr,
        approval_addr,
        approval_origin,
        task_id,
    }))
}

fn next_value<I: Iterator<Item = String>>(it: &mut I, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} attend une valeur"))
}

/// Le texte d'aide, pour que `main.rs` l'affiche sur `--help`/erreur sans dupliquer la chaîne.
pub fn usage() -> &'static str {
    USAGE
}

/// La PKI chargée depuis `cert-dir`, sous la forme exacte attendue par les deux serveurs.
pub struct LoadedCerts {
    /// Chaîne du certificat serveur mTLS + sa clé (pour `build_server_config`).
    pub mtls_server_chain: Vec<CertificateDer<'static>>,
    pub mtls_server_key: PrivateKeyDer<'static>,
    /// Racines de confiance pour vérifier les certificats CLIENTS (la CA).
    pub ca_roots: Arc<RootCertStore>,
    /// PEM bruts du serveur d'approbation (`serve_https` prend directement des `Vec<u8>` PEM).
    pub approval_cert_pem: Vec<u8>,
    pub approval_key_pem: Vec<u8>,
}

/// Lit un fichier en signalant lisiblement quel fichier a échoué (les erreurs d'I/O nues ne
/// disent pas lequel).
fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("lecture de {}: {e}", path.display()))
}

/// Charge la PKI attendue par le service depuis `cert_dir` (fichiers produits par
/// `helixos-provision`). Toute erreur (fichier absent, PEM illisible, clé absente) est renvoyée
/// avec un message identifiant le fichier — jamais un `unwrap`/panic.
pub fn load_certs(cert_dir: &Path) -> Result<LoadedCerts, String> {
    // --- Certificat serveur mTLS + clé ---
    let mtls_cert_bytes = read_file(&cert_dir.join("mtls-server.pem"))?;
    let mtls_server_chain = certs_from_pem(&mtls_cert_bytes, "mtls-server.pem")?;
    if mtls_server_chain.is_empty() {
        return Err("mtls-server.pem ne contient aucun certificat".into());
    }
    let mtls_key_bytes = read_file(&cert_dir.join("mtls-server.key"))?;
    let mtls_server_key = key_from_pem(&mtls_key_bytes, "mtls-server.key")?;

    // --- CA -> racines de confiance pour vérifier les certificats clients ---
    let ca_bytes = read_file(&cert_dir.join("ca.pem"))?;
    let ca_chain = certs_from_pem(&ca_bytes, "ca.pem")?;
    if ca_chain.is_empty() {
        return Err("ca.pem ne contient aucun certificat".into());
    }
    let mut roots = RootCertStore::empty();
    for (i, cert) in ca_chain.into_iter().enumerate() {
        roots
            .add(cert)
            .map_err(|e| format!("ajout du certificat CA #{i} (ca.pem) aux racines: {e}"))?;
    }
    let ca_roots = Arc::new(roots);

    // --- PEM du serveur d'approbation (transmis tels quels à serve_https) ---
    let approval_cert_pem = read_file(&cert_dir.join("approval-server.pem"))?;
    // Valide tôt que le PEM contient bien un certificat (échoue au démarrage, pas au 1er GET).
    if certs_from_pem(&approval_cert_pem, "approval-server.pem")?.is_empty() {
        return Err("approval-server.pem ne contient aucun certificat".into());
    }
    let approval_key_pem = read_file(&cert_dir.join("approval-server.key"))?;

    Ok(LoadedCerts { mtls_server_chain, mtls_server_key, ca_roots, approval_cert_pem, approval_key_pem })
}

fn certs_from_pem(pem: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("PEM de certificat illisible ({label}): {e}"))
}

fn key_from_pem(pem: &[u8], label: &str) -> Result<PrivateKeyDer<'static>, String> {
    rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| format!("PEM de clé illisible ({label}): {e}"))?
        .ok_or_else(|| format!("aucune clé privée trouvée dans {label}"))
}

/// Le service assemblé, prêt à être servi : les deux serveurs déjà liés sur leurs adresses
/// respectives, tous deux capturant le MÊME [`SharedKernel`].
///
/// La liaison des ports est faite AVANT de servir (fonction [`bind`]) pour que l'appelant — en
/// particulier le test d'assemblage — connaisse les adresses effectives (utile pour un port
/// `:0` choisi par l'OS) et puisse se connecter dès le retour, sans course de démarrage.
pub struct Service {
    pub kernel: SharedKernel,
    pub mtls_listener: TcpListener,
    pub mtls_server_config: Arc<rustls::ServerConfig>,
    pub approval_listener: std::net::TcpListener,
    pub approval_router: axum::Router,
    pub approval_cert_pem: Vec<u8>,
    pub approval_key_pem: Vec<u8>,
    /// Adresses effectives (après liaison), pour diagnostic/tests.
    pub mtls_addr: std::net::SocketAddr,
    pub approval_addr: std::net::SocketAddr,
}

/// Assemble le service : crée le noyau PARTAGÉ (un seul `Arc<Mutex<Kernel>>`), charge la PKI, et
/// LIE les deux ports. Ne sert pas encore (voir [`Service::serve`]) — la séparation liaison/service
/// laisse l'appelant lire les adresses effectives avant de lancer les boucles.
///
/// Le point d'assemblage est ici : `build_router(kernel.clone())` et le serveur mTLS reçoivent des
/// clones du MÊME `SharedKernel`. Aucune de ces deux surfaces ne construit son propre noyau isolé.
pub async fn bind(config: &Config) -> Result<Service, String> {
    let certs = load_certs(&config.cert_dir)?;

    // LE noyau partagé — construit une seule fois, partagé par les deux serveurs.
    let kernel = Kernel::new(config.state_dir.clone(), config.lease())
        .map_err(|e| format!("création du noyau (state-dir {}): {e}", config.state_dir.display()))?;
    let kernel: SharedKernel = Arc::new(tokio::sync::Mutex::new(kernel));

    // Serveur mTLS : ServerConfig ancré sur la CA (vérifie les certs clients).
    let mtls_server_config =
        build_server_config(certs.ca_roots.clone(), server_leaf(&certs)?, certs.mtls_server_key);
    let mtls_listener = TcpListener::bind(&config.mtls_addr)
        .await
        .map_err(|e| format!("liaison du serveur mTLS sur {}: {e}", config.mtls_addr))?;
    let mtls_addr = mtls_listener
        .local_addr()
        .map_err(|e| format!("adresse locale mTLS: {e}"))?;

    // Serveur d'approbation : router branché sur le MÊME noyau partagé.
    let approval_router = build_router(kernel.clone());
    let approval_listener = std::net::TcpListener::bind(&config.approval_addr)
        .map_err(|e| format!("liaison de la page d'approbation sur {}: {e}", config.approval_addr))?;
    // `axum-server`/`from_tcp` gère l'acceptation en asynchrone : le listener std doit être non
    // bloquant, sinon `accept()` bloquerait un thread de l'executor tokio.
    approval_listener
        .set_nonblocking(true)
        .map_err(|e| format!("passage du listener d'approbation en non bloquant: {e}"))?;
    let approval_addr = approval_listener
        .local_addr()
        .map_err(|e| format!("adresse locale d'approbation: {e}"))?;

    Ok(Service {
        kernel,
        mtls_listener,
        mtls_server_config,
        approval_listener,
        approval_router,
        approval_cert_pem: certs.approval_cert_pem,
        approval_key_pem: certs.approval_key_pem,
        mtls_addr,
        approval_addr,
    })
}

/// `build_server_config` consomme la chaîne par valeur mais on n'a besoin que de la feuille de
/// tête (le certificat serveur). Extrait la 1re et vérifie qu'elle existe (déjà garanti par
/// `load_certs`, mais on ne panique pas ici).
fn server_leaf(certs: &LoadedCerts) -> Result<CertificateDer<'static>, String> {
    certs
        .mtls_server_chain
        .first()
        .cloned()
        .ok_or_else(|| "mtls-server.pem ne contient aucun certificat".into())
}

impl Service {
    /// Sert les DEUX serveurs en concurrence sur le noyau partagé jusqu'à ce que `shutdown` se
    /// résolve (Ctrl-C en production) OU qu'un des serveurs s'arrête sur erreur. `tokio::select!`
    /// (pas `join!`) : dès que l'un des trois bras se termine, on rend la main proprement — un
    /// serveur qui meurt ne doit pas laisser l'autre tourner en aveugle.
    ///
    /// Renvoie `Ok(())` sur arrêt demandé (shutdown), `Err` si un serveur s'est arrêté sur erreur.
    pub async fn serve<S>(self, shutdown: S) -> Result<(), String>
    where
        S: std::future::Future<Output = ()>,
    {
        let mtls = serve_mtls(self.mtls_listener, self.kernel.clone(), self.mtls_server_config);
        let approval = serve_https(
            self.approval_listener,
            self.approval_cert_pem,
            self.approval_key_pem,
            self.approval_router,
        );

        tokio::select! {
            r = mtls => r.map_err(|e| format!("serveur mTLS arrêté: {e}")),
            r = approval => r.map_err(|e| format!("page d'approbation arrêtée: {e}")),
            () = shutdown => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env vide (aucune variable) — pour tester le parsing d'args seul.
    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_config_applies_defaults() {
        let outcome = parse_config(
            args(&["--state-dir", "st", "--vault-root", "vault", "--cert-dir", "certs"]),
            no_env,
        )
        .unwrap();
        let ParseOutcome::Run(cfg) = outcome else { panic!("attendu Run") };
        assert_eq!(cfg.state_dir, PathBuf::from("st"));
        assert_eq!(cfg.vault_roots, vec![PathBuf::from("vault")]);
        assert_eq!(cfg.cert_dir, PathBuf::from("certs"));
        assert_eq!(cfg.mtls_addr, DEFAULT_MTLS_ADDR);
        assert_eq!(cfg.approval_addr, DEFAULT_APPROVAL_ADDR);
        assert_eq!(cfg.approval_origin, DEFAULT_APPROVAL_ORIGIN);
        assert_eq!(cfg.task_id, DEFAULT_TASK_ID);
    }

    #[test]
    fn parse_config_overrides_all() {
        let outcome = parse_config(
            args(&[
                "--state-dir", "st",
                "--vault-root", "v1",
                "--vault-root", "v2",
                "--cert-dir", "certs",
                "--mtls-addr", "0.0.0.0:1",
                "--approval-addr", "0.0.0.0:2",
                "--approval-origin", "https://helix.ts.net",
                "--task-id", "job-7",
            ]),
            no_env,
        )
        .unwrap();
        let ParseOutcome::Run(cfg) = outcome else { panic!("attendu Run") };
        assert_eq!(cfg.vault_roots, vec![PathBuf::from("v1"), PathBuf::from("v2")]);
        assert_eq!(cfg.mtls_addr, "0.0.0.0:1");
        assert_eq!(cfg.approval_addr, "0.0.0.0:2");
        assert_eq!(cfg.approval_origin, "https://helix.ts.net");
        assert_eq!(cfg.task_id, "job-7");
    }

    #[test]
    fn parse_config_reads_env_when_arg_absent() {
        let env = |k: &str| match k {
            "HELIXOS_STATE_DIR" => Some("env-st".to_string()),
            "HELIXOS_VAULT_ROOT" => Some("env-vault".to_string()),
            "HELIXOS_CERT_DIR" => Some("env-certs".to_string()),
            "HELIXOS_MTLS_ADDR" => Some("1.2.3.4:9".to_string()),
            _ => None,
        };
        let outcome = parse_config(args(&[]), env).unwrap();
        let ParseOutcome::Run(cfg) = outcome else { panic!("attendu Run") };
        assert_eq!(cfg.state_dir, PathBuf::from("env-st"));
        assert_eq!(cfg.vault_roots, vec![PathBuf::from("env-vault")]);
        assert_eq!(cfg.cert_dir, PathBuf::from("env-certs"));
        assert_eq!(cfg.mtls_addr, "1.2.3.4:9");
    }

    #[test]
    fn parse_config_arg_beats_env() {
        let env = |k: &str| match k {
            "HELIXOS_MTLS_ADDR" => Some("from-env:1".to_string()),
            _ => None,
        };
        let outcome = parse_config(
            args(&["--state-dir", "st", "--vault-root", "v", "--cert-dir", "c", "--mtls-addr", "from-arg:2"]),
            env,
        )
        .unwrap();
        let ParseOutcome::Run(cfg) = outcome else { panic!("attendu Run") };
        assert_eq!(cfg.mtls_addr, "from-arg:2", "l'argument doit primer sur l'environnement");
    }

    #[test]
    fn parse_config_requires_state_dir() {
        let err = parse_config(args(&["--vault-root", "v", "--cert-dir", "c"]), no_env).unwrap_err();
        assert!(err.contains("--state-dir"), "{err}");
    }

    #[test]
    fn parse_config_requires_vault_root() {
        let err = parse_config(args(&["--state-dir", "s", "--cert-dir", "c"]), no_env).unwrap_err();
        assert!(err.contains("--vault-root"), "{err}");
    }

    #[test]
    fn parse_config_requires_cert_dir() {
        let err = parse_config(args(&["--state-dir", "s", "--vault-root", "v"]), no_env).unwrap_err();
        assert!(err.contains("--cert-dir"), "{err}");
    }

    #[test]
    fn parse_config_rejects_unknown_option() {
        let err = parse_config(args(&["--frobnicate"]), no_env).unwrap_err();
        assert!(err.contains("inconnue"), "{err}");
    }

    #[test]
    fn parse_config_flag_missing_value_errors() {
        let err = parse_config(args(&["--state-dir"]), no_env).unwrap_err();
        assert!(err.contains("attend une valeur"), "{err}");
    }

    #[test]
    fn parse_config_help_short_circuits() {
        assert!(matches!(parse_config(args(&["--help"]), no_env).unwrap(), ParseOutcome::Help));
        assert!(matches!(parse_config(args(&["-h"]), no_env).unwrap(), ParseOutcome::Help));
    }

    #[test]
    fn load_certs_reports_missing_dir_cleanly() {
        // Un cert-dir inexistant doit produire une erreur lisible identifiant le fichier, pas un panic.
        // (`LoadedCerts` ne dérive PAS `Debug` — il contient du matériel de clé — donc on ne peut
        // pas utiliser `unwrap_err()` ; on discrimine explicitement sur le variant `Err`.)
        let missing = std::env::temp_dir().join(format!("helix-nope-{}", std::process::id()));
        match load_certs(&missing) {
            Err(err) => assert!(
                err.contains("mtls-server.pem"),
                "l'erreur doit nommer le fichier manquant: {err}"
            ),
            Ok(_) => panic!("un cert-dir inexistant doit échouer"),
        }
    }
}
