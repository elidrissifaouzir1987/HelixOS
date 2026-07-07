#![forbid(unsafe_code)]
//! `helixos-provision` — génère la PKI locale de HelixOS sur disque (bootstrap MVP-0).
//!
//! Le binaire de runtime `helixos-kernel` CHARGE des certificats provisionnés hors bande ; il ne
//! les génère jamais (il n'embarque donc pas `rcgen`). Ce binaire séparé — le SEUL du workspace à
//! dépendre de `rcgen` — produit la chaîne complète nécessaire au bootstrap :
//!
//!   - une **CA** locale auto-signée (racine de confiance commune) ;
//!   - un **certificat serveur mTLS** (SAN `localhost` + `127.0.0.1`) présenté aux appelants ;
//!   - un **certificat serveur d'approbation** (SAN = le nom d'origine d'approbation, défaut
//!     `localhost`) présenté au navigateur sur la page HTTPS ;
//!   - un **certificat client** (CN = identité de l'appelant) pour le shim MCP / les appelants.
//!
//! Tous les certs feuilles sont signés par la MÊME CA, de sorte que :
//!   - le `WebPkiClientVerifier` du serveur mTLS (ancré sur cette CA) accepte le cert client ;
//!   - un client qui fait confiance à cette CA valide les deux certs serveur.
//!
//! Fichiers écrits dans `--out <dir>` :
//!   `ca.pem`, `mtls-server.pem`/`mtls-server.key`, `approval-server.pem`/`approval-server.key`,
//!   `client.pem`/`client.key`.
//!
//! Idempotence / sûreté : refuse d'écraser un fichier existant sauf si `--force` est passé (une
//! régénération accidentelle invaliderait des certs déjà distribués). En cas de refus, AUCUN
//! fichier n'est modifié (la collision est détectée avant toute écriture).

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Nom des fichiers produits, relativement à `--out`. Regroupé ici pour que le contrôle
/// anti-écrasement (avant toute écriture) et l'écriture réelle parcourent EXACTEMENT le même
/// ensemble — impossible d'écrire un fichier qui aurait échappé au contrôle de collision.
struct OutputPaths {
    ca_pem: PathBuf,
    mtls_cert: PathBuf,
    mtls_key: PathBuf,
    approval_cert: PathBuf,
    approval_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl OutputPaths {
    fn under(dir: &Path) -> Self {
        Self {
            ca_pem: dir.join("ca.pem"),
            mtls_cert: dir.join("mtls-server.pem"),
            mtls_key: dir.join("mtls-server.key"),
            approval_cert: dir.join("approval-server.pem"),
            approval_key: dir.join("approval-server.key"),
            client_cert: dir.join("client.pem"),
            client_key: dir.join("client.key"),
        }
    }

    /// Tous les chemins, dans un ordre stable — pour le contrôle de collision ET l'écriture.
    fn all(&self) -> [&PathBuf; 7] {
        [
            &self.ca_pem,
            &self.mtls_cert,
            &self.mtls_key,
            &self.approval_cert,
            &self.approval_key,
            &self.client_cert,
            &self.client_key,
        ]
    }
}

/// Configuration résolue depuis les arguments de ligne de commande.
#[derive(Debug)]
struct Config {
    out: PathBuf,
    /// Nom d'origine du serveur d'approbation → SAN de `approval-server.pem` (défaut `localhost`).
    approval_name: String,
    /// CN du certificat client, identité de l'appelant côté serveur mTLS (défaut `helix-caller`).
    client_cn: String,
    force: bool,
}

const USAGE: &str = "\
helixos-provision — génère la PKI locale de HelixOS

USAGE:
    helixos-provision --out <DIR> [--approval-name <NAME>] [--client-cn <CN>] [--force]

OPTIONS:
    --out <DIR>              Répertoire de sortie des certificats (requis).
    --approval-name <NAME>   SAN du certificat serveur d'approbation (défaut: localhost).
    --client-cn <CN>         CN du certificat client / identité de l'appelant (défaut: helix-caller).
    --force                  Écrase les fichiers existants (sinon: refus si un fichier existe déjà).
    -h, --help               Affiche cette aide.
";

/// Parse les arguments sans dépendance externe (jeu d'options fixe et petit). Renvoie `Err` avec
/// un message lisible sur toute option inconnue ou valeur manquante ; `Ok(None)` pour `--help`.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Config>, String> {
    let mut out: Option<PathBuf> = None;
    let mut approval_name = String::from("localhost");
    let mut client_cn = String::from("helix-caller");
    let mut force = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--force" => force = true,
            "--out" => {
                let v = args.next().ok_or("--out attend un répertoire")?;
                out = Some(PathBuf::from(v));
            }
            "--approval-name" => {
                approval_name = args.next().ok_or("--approval-name attend une valeur")?;
            }
            "--client-cn" => {
                client_cn = args.next().ok_or("--client-cn attend une valeur")?;
            }
            other => return Err(format!("option inconnue: {other}")),
        }
    }

    let out = out.ok_or("--out <DIR> est requis")?;
    Ok(Some(Config { out, approval_name, client_cn, force }))
}

/// Une feuille générée : cert + clé, tous deux au format PEM (ce que le runtime charge via
/// `rustls-pemfile`).
struct LeafPem {
    cert_pem: String,
    key_pem: String,
}

/// Rôle d'une feuille — détermine son ExtendedKeyUsage (et si `keyEncipherment` est pertinent).
/// OpenSSL 3.x strict n'exige pas d'EKU sur une feuille, mais un navigateur / une politique TLS
/// stricte veut serverAuth sur un cert serveur et clientAuth sur un cert présenté en client ; on
/// les pose explicitement pour que les certs soient pleinement utilisables (browser-trustable).
#[derive(Clone, Copy)]
enum LeafRole {
    /// Cert présenté par un serveur TLS → EKU serverAuth (+ keyEncipherment, utile aux suites RSA).
    Server,
    /// Cert présenté par un client mTLS → EKU clientAuth.
    Client,
}

/// Génère une feuille (serveur ou client) signée par la CA fournie. `sans` deviennent les Subject
/// Alternative Names (rcgen classe automatiquement une valeur ressemblant à une IP, ex.
/// `127.0.0.1`, en SAN IP, et le reste en SAN DNS). `cn` renseigne le Common Name du sujet
/// (identité de l'appelant pour un cert client ; libellé du serveur sinon). `role` fixe le
/// KeyUsage/EKU (serverAuth pour un serveur, clientAuth pour un client).
fn generate_leaf(
    cn: &str,
    sans: Vec<String>,
    role: LeafRole,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
) -> Result<LeafPem, String> {
    let key = KeyPair::generate().map_err(|e| format!("génération de clé pour {cn}: {e}"))?;
    let mut params =
        CertificateParams::new(sans).map_err(|e| format!("SANs invalides pour {cn}: {e}"))?;
    params.distinguished_name.push(DnType::CommonName, cn);
    // FIX KeyUsage/EKU feuille : une feuille TLS doit porter KeyUsage.digitalSignature (elle signe
    // l'échange de clés du handshake) et l'EKU adapté à son rôle. Sans EKU, un client TLS strict /
    // navigateur peut refuser d'utiliser le cert pour l'authentification serveur ou client.
    match role {
        LeafRole::Server => {
            // digitalSignature (ECDSA/ECDHE) + keyEncipherment (suites RSA classiques) ; serverAuth.
            params.key_usages =
                vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        LeafRole::Client => {
            // Un cert client n'a pas besoin de keyEncipherment ; digitalSignature suffit ; clientAuth.
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
    }
    // FIX AKI : émettre l'extension Authority Key Identifier sur la feuille. rcgen ne l'écrit QUE si
    // ce drapeau est vrai (défaut : faux → aucune AKI, d'où le rejet OpenSSL 3.x/Python 3.13
    // « Missing Authority Key Identifier »). rcgen dérive alors l'AKI depuis la `KeyIdMethod` de
    // l'émetteur appliquée à la SPKI de la CA — soit exactement la SKI de la CA (même méthode,
    // même clé) : la chaîne feuille↔CA se lie donc et se vérifie sous OpenSSL strict / navigateur.
    params.use_authority_key_identifier_extension = true;
    // Même méthode de dérivation que la CA (SHA-256 tronqué, RFC 7093) → AKI feuille == SKI CA.
    params.key_identifier_method = KeyIdMethod::Sha256;
    let issuer = Issuer::from_params(ca_params, ca_key);
    let cert = params
        .signed_by(&key, &issuer)
        .map_err(|e| format!("signature de {cn} par la CA: {e}"))?;
    Ok(LeafPem { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
}

/// Génère la CA + les 3 feuilles (serveur mTLS, serveur d'approbation, client), toutes signées par
/// cette même CA. Renvoie la PKI complète en PEM, PRÊTE à écrire (rien n'est encore touché sur
/// disque — l'écriture est décidée en aval, après le contrôle anti-écrasement).
struct Pki {
    ca_pem: String,
    mtls: LeafPem,
    approval: LeafPem,
    client: LeafPem,
}

fn generate_pki(config: &Config) -> Result<Pki, String> {
    // CA locale auto-signée : racine de confiance commune aux deux serveurs et au client.
    let ca_key = KeyPair::generate().map_err(|e| format!("génération de la clé de la CA: {e}"))?;
    let mut ca_params =
        CertificateParams::new(vec!["HelixOS Local CA".into()]).map_err(|e| format!("params de CA: {e}"))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "HelixOS Local CA");
    // FIX KeyUsage CA : émettre l'extension KeyUsage sur la CA avec keyCertSign (+ cRLSign). C'est
    // l'extension qui manquait APRÈS le fix AKI : OpenSSL 3.x `-x509_strict` (et donc navigateur /
    // curl-openssl / Python) rejetait la chaîne avec « CA cert does not include key usage extension »
    // car un cert qui signe des feuilles DOIT porter keyCertSign (RFC 5280 §4.2.1.3). cRLSign est
    // ajouté pour que la CA puisse aussi signer une CRL (cohérent avec un rôle de CA complet).
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // La CA (is_ca) émet toujours un Subject Key Identifier ; on épingle la méthode de dérivation
    // (SHA-256 tronqué) explicitement pour que la SKI de la CA et l'AKI des feuilles (même méthode,
    // même clé émettrice) coïncident quoi qu'il arrive au défaut de rcgen dans le futur.
    ca_params.key_identifier_method = KeyIdMethod::Sha256;
    let ca_cert =
        ca_params.clone().self_signed(&ca_key).map_err(|e| format!("auto-signature de la CA: {e}"))?;

    // Serveur mTLS : présenté aux appelants ; SAN `localhost` + boucle locale IPv4. Rôle serveur
    // (le noyau présente ce cert côté serveur ; l'identité cliente est le cert `client` distinct).
    let mtls = generate_leaf(
        "helixos-kernel-mtls",
        vec!["localhost".into(), "127.0.0.1".into()],
        LeafRole::Server,
        &ca_params,
        &ca_key,
    )?;

    // Serveur d'approbation : SAN = le nom d'origine sous lequel le navigateur atteint la page.
    let approval = generate_leaf(
        "helixos-kernel-approval",
        vec![config.approval_name.clone()],
        LeafRole::Server,
        &ca_params,
        &ca_key,
    )?;

    // Client : CN = identité de l'appelant, dérivée côté serveur depuis ce cert (jamais du réseau).
    // Rôle client (présenté par le shim MCP au `WebPkiClientVerifier` du noyau) → EKU clientAuth.
    let client = generate_leaf(
        &config.client_cn,
        vec![config.client_cn.clone()],
        LeafRole::Client,
        &ca_params,
        &ca_key,
    )?;

    Ok(Pki { ca_pem: ca_cert.pem(), mtls, approval, client })
}

/// Écrit la PKI sur disque, APRÈS avoir vérifié qu'aucun fichier de sortie n'existe déjà (sauf
/// `--force`). Le contrôle de collision est fait AVANT toute écriture, sur l'ensemble complet des
/// chemins : soit tout est écrit, soit rien ne l'est (pas d'état PKI partiel sur un refus).
fn write_pki(config: &Config, pki: &Pki) -> Result<(), String> {
    std::fs::create_dir_all(&config.out)
        .map_err(|e| format!("création du répertoire de sortie {}: {e}", config.out.display()))?;

    let paths = OutputPaths::under(&config.out);
    if !config.force {
        let existing: Vec<String> = paths
            .all()
            .iter()
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            return Err(format!(
                "refus d'écraser {} fichier(s) existant(s) sans --force:\n  {}",
                existing.len(),
                existing.join("\n  ")
            ));
        }
    }

    // À ce stade, l'écriture est autorisée. Chaque write est vérifiée individuellement.
    let writes: [(&PathBuf, &str); 7] = [
        (&paths.ca_pem, &pki.ca_pem),
        (&paths.mtls_cert, &pki.mtls.cert_pem),
        (&paths.mtls_key, &pki.mtls.key_pem),
        (&paths.approval_cert, &pki.approval.cert_pem),
        (&paths.approval_key, &pki.approval.key_pem),
        (&paths.client_cert, &pki.client.cert_pem),
        (&paths.client_key, &pki.client.key_pem),
    ];
    for (path, contents) in writes {
        std::fs::write(path, contents)
            .map_err(|e| format!("écriture de {}: {e}", path.display()))?;
    }
    Ok(())
}

fn run(config: Config) -> Result<(), String> {
    let pki = generate_pki(&config)?;
    write_pki(&config, &pki)?;
    let paths = OutputPaths::under(&config.out);
    println!("PKI HelixOS générée dans {}:", config.out.display());
    for p in paths.all() {
        println!("  {}", p.display());
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Ok(None) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Some(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("erreur: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("erreur: {e}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_out() -> PathBuf {
        // Répertoire temporaire unique par test (pas de dépendance externe type `tempfile`/`uuid`).
        // Un compteur atomique process-global garantit l'unicité entre tests concurrents ; le
        // timestamp nanoseconde évite les collisions entre exécutions successives. On formate en
        // nombres purs — jamais `{:?}` d'un `SystemTime` (qui produit des `{ }`, invalides dans un
        // chemin Windows).
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("helix-provision-test-{}-{n}-{nanos}", std::process::id()))
    }

    fn config_at(out: PathBuf, force: bool) -> Config {
        Config { out, approval_name: "localhost".into(), client_cn: "helix-caller".into(), force }
    }

    #[test]
    fn parse_args_requires_out() {
        let err = parse_args(["--force".to_string()].into_iter()).unwrap_err();
        assert!(err.contains("--out"), "l'absence de --out doit être signalée: {err}");
    }

    #[test]
    fn parse_args_reads_all_options() {
        let cfg = parse_args(
            [
                "--out",
                "somedir",
                "--approval-name",
                "helix.example.ts.net",
                "--client-cn",
                "shim-1",
                "--force",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap()
        .expect("config attendue (pas --help)");
        assert_eq!(cfg.out, PathBuf::from("somedir"));
        assert_eq!(cfg.approval_name, "helix.example.ts.net");
        assert_eq!(cfg.client_cn, "shim-1");
        assert!(cfg.force);
    }

    #[test]
    fn parse_args_rejects_unknown_option() {
        let err = parse_args(["--nope".to_string()].into_iter()).unwrap_err();
        assert!(err.contains("inconnue"), "option inconnue doit être signalée: {err}");
    }

    #[test]
    fn parse_args_help_returns_none() {
        assert!(parse_args(["--help".to_string()].into_iter()).unwrap().is_none());
    }

    /// Extrait, d'un cert PEM, le Subject Key Identifier (octets bruts) s'il est présent.
    fn subject_key_id(cert_pem: &str) -> Option<Vec<u8>> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parsable");
        let (_, cert) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("cert DER parsable");
        // Le résultat est `Vec<u8>` (possédé) ; on le lie avant la fin du bloc pour que l'itérateur
        // temporaire (qui emprunte `cert`) soit relâché avant `cert` (sinon E0597).
        let id = cert.iter_extensions().find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => {
                Some(id.0.to_vec())
            }
            _ => None,
        });
        id
    }

    /// Extrait, d'un cert PEM, le keyIdentifier de l'Authority Key Identifier s'il est présent.
    fn authority_key_id(cert_pem: &str) -> Option<Vec<u8>> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parsable");
        let (_, cert) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("cert DER parsable");
        let id = cert.iter_extensions().find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|k| k.0.to_vec())
            }
            _ => None,
        });
        id
    }

    /// Vrai si le cert PEM porte BasicConstraints CA:TRUE.
    fn is_ca(cert_pem: &str) -> bool {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parsable");
        let (_, cert) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("cert DER parsable");
        cert.is_ca()
    }

    /// Extrait l'extension KeyUsage (les drapeaux bruts) d'un cert PEM si elle est présente.
    /// OpenSSL 3.x `-x509_strict` EXIGE cette extension sur un cert de CA (« CA cert does not
    /// include key usage extension ») : son absence est précisément ce qui bloquait le drive live.
    fn key_usage(cert_pem: &str) -> Option<x509_parser::extensions::KeyUsage> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parsable");
        let (_, cert) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("cert DER parsable");
        let ku = cert.iter_extensions().find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::KeyUsage(ku) => Some(*ku),
            _ => None,
        });
        ku
    }

    /// Extrait, d'un cert PEM, les deux drapeaux ExtendedKeyUsage qui nous intéressent
    /// `(server_auth, client_auth)` si l'extension EKU est présente.
    fn extended_key_usage(cert_pem: &str) -> Option<(bool, bool)> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parsable");
        let (_, cert) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("cert DER parsable");
        let eku = cert.iter_extensions().find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
                Some((eku.server_auth, eku.client_auth))
            }
            _ => None,
        });
        eku
    }

    /// PREUVE que le trou AKI est fermé (drive live : OpenSSL 3.x / Python 3.13 rejetaient la chaîne
    /// « Missing Authority Key Identifier »). Ce test ÉCHOUE sans le fix (les feuilles n'avaient
    /// aucune extension AKI → `authority_key_id` renvoie `None`). Il asserte, via `x509-parser`
    /// (déterministe, aucune dépendance externe) :
    ///   - la CA porte un Subject Key Identifier ET BasicConstraints CA:TRUE ;
    ///   - chaque feuille (mtls-server, approval-server, client) porte un Authority Key Identifier
    ///     avec un keyIdentifier, N'est PAS une CA, et son AKI == la SKI de la CA — c.-à-d. la
    ///     liaison exacte qu'OpenSSL exige pour construire/vérifier la chaîne feuille↔CA.
    #[test]
    fn leaves_carry_aki_matching_ca_ski_so_chain_verifies_strictly() {
        let cfg = config_at(temp_out(), false);
        let pki = generate_pki(&cfg).expect("génération PKI");

        // CA : SKI présent + CA:TRUE.
        let ca_ski = subject_key_id(&pki.ca_pem)
            .expect("la CA doit porter un Subject Key Identifier (racine de la liaison)");
        assert!(!ca_ski.is_empty(), "la SKI de la CA ne doit pas être vide");
        assert!(is_ca(&pki.ca_pem), "la CA doit porter BasicConstraints CA:TRUE");

        // Chaque feuille : AKI présent, == SKI de la CA, et non-CA.
        for (label, leaf) in [
            ("mtls-server", &pki.mtls),
            ("approval-server", &pki.approval),
            ("client", &pki.client),
        ] {
            let aki = authority_key_id(&leaf.cert_pem).unwrap_or_else(|| {
                panic!("{label}: feuille SANS Authority Key Identifier — OpenSSL rejette la chaîne")
            });
            assert_eq!(
                aki, ca_ski,
                "{label}: l'AKI de la feuille doit référencer la SKI de la CA (liaison de chaîne)"
            );
            assert!(!is_ca(&leaf.cert_pem), "{label}: une feuille ne doit PAS être une CA");
        }
    }

    /// PREUVE que le trou KeyUsage/EKU est fermé (drive live : OpenSSL 3.x `-x509_strict` rejetait
    /// la chaîne « CA cert does not include key usage extension » APRÈS le fix AKI). Ce test ÉCHOUE
    /// sans le fix KeyUsage/EKU (la CA n'a AUCUNE extension KeyUsage → `key_usage(&ca)` renvoie
    /// `None` → premier `expect` en panique). Il asserte, via `x509-parser` (déterministe, aucun
    /// binaire externe) — en plus des SKI/AKI déjà couverts :
    ///   - la CA porte KeyUsage avec keyCertSign (+ cRLSign) — l'extension qu'OpenSSL strict exige
    ///     sur tout cert signeur ;
    ///   - chaque feuille porte KeyUsage(digitalSignature) ;
    ///   - les serveurs (mtls, approval) portent EKU serverAuth ; le client porte EKU clientAuth.
    #[test]
    fn certs_carry_keyusage_and_eku_for_strict_openssl() {
        let cfg = config_at(temp_out(), false);
        let pki = generate_pki(&cfg).expect("génération PKI");

        // CA : KeyUsage présent, avec keyCertSign (signe des certs) ET cRLSign (signe des CRL).
        let ca_ku = key_usage(&pki.ca_pem).expect(
            "la CA DOIT porter une extension KeyUsage (sinon OpenSSL 3.x strict: « CA cert does \
             not include key usage extension »)",
        );
        assert!(
            ca_ku.key_cert_sign(),
            "la CA doit porter KeyUsage.keyCertSign (elle signe les feuilles)"
        );
        assert!(ca_ku.crl_sign(), "la CA doit porter KeyUsage.cRLSign");

        // Serveurs : KeyUsage.digitalSignature + EKU.serverAuth.
        for (label, leaf) in [("mtls-server", &pki.mtls), ("approval-server", &pki.approval)] {
            let ku = key_usage(&leaf.cert_pem)
                .unwrap_or_else(|| panic!("{label}: feuille SANS extension KeyUsage"));
            assert!(
                ku.digital_signature(),
                "{label}: un cert serveur doit porter KeyUsage.digitalSignature"
            );
            let (server_auth, _client_auth) = extended_key_usage(&leaf.cert_pem)
                .unwrap_or_else(|| panic!("{label}: feuille SANS ExtendedKeyUsage"));
            assert!(server_auth, "{label}: un cert serveur doit porter EKU serverAuth");
        }

        // Client : KeyUsage.digitalSignature + EKU.clientAuth.
        let client_ku = key_usage(&pki.client.cert_pem)
            .expect("le cert client doit porter une extension KeyUsage");
        assert!(
            client_ku.digital_signature(),
            "le cert client doit porter KeyUsage.digitalSignature"
        );
        let (_server_auth, client_auth) = extended_key_usage(&pki.client.cert_pem)
            .expect("le cert client doit porter ExtendedKeyUsage");
        assert!(client_auth, "le cert client doit porter EKU clientAuth");
    }

    /// PREUVE la plus fidèle à OpenSSL 3.x : écrit la CA + les feuilles sur disque et invoque le VRAI
    /// binaire `openssl verify -x509_strict -CAfile ca.pem <feuille>.pem`, qui applique exactement la
    /// politique stricte qui a rejeté la chaîne lors du drive live (AKI manquant, puis KeyUsage
    /// manquant sur la CA). Exige exit 0 pour la feuille serveur d'approbation ET le cert client.
    /// SKIP propre (via `eprintln!`) si `openssl` est absent de l'environnement — le test
    /// `certs_carry_keyusage_and_eku_for_strict_openssl` (toujours actif) reste alors la preuve.
    /// Ce test ÉCHOUE sans le fix KeyUsage : `openssl verify -x509_strict` sortait alors non-zéro
    /// avec « CA cert does not include key usage extension ».
    #[test]
    fn openssl_strict_verify_accepts_chain() {
        // Résout `openssl` : soit un chemin explicite via $OPENSSL, soit `openssl` sur le PATH.
        let openssl = std::env::var("OPENSSL").unwrap_or_else(|_| "openssl".to_string());
        // Sonde de disponibilité : `openssl version`. Toute erreur de lancement => SKIP.
        match std::process::Command::new(&openssl).arg("version").output() {
            Ok(out) if out.status.success() => {}
            _ => {
                eprintln!(
                    "SKIP openssl_strict_verify_accepts_chain: binaire `openssl` indisponible \
                     (défini $OPENSSL pour le pointer). La preuve x509-parser reste active."
                );
                return;
            }
        }

        let out = temp_out();
        let cfg = config_at(out.clone(), false);
        let pki = generate_pki(&cfg).expect("génération PKI");
        write_pki(&cfg, &pki).expect("écriture PKI");
        let paths = OutputPaths::under(&out);

        for (label, leaf_path) in
            [("approval-server", &paths.approval_cert), ("client", &paths.client_cert)]
        {
            let output = std::process::Command::new(&openssl)
                .arg("verify")
                .arg("-x509_strict")
                .arg("-CAfile")
                .arg(&paths.ca_pem)
                .arg(leaf_path)
                .output()
                .expect("lancement de `openssl verify`");
            assert!(
                output.status.success(),
                "openssl verify -x509_strict a REJETÉ {label} (la chaîne n'est pas conforme \
                 OpenSSL 3.x strict):\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn generate_pki_produces_four_pem_bundles() {
        let cfg = config_at(temp_out(), false);
        let pki = generate_pki(&cfg).expect("génération PKI");
        // Chaque bundle est bien un PEM plausible (marqueur BEGIN présent).
        assert!(pki.ca_pem.contains("BEGIN CERTIFICATE"), "CA doit être un cert PEM");
        assert!(pki.mtls.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(pki.mtls.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(pki.approval.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(pki.approval.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(pki.client.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(pki.client.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn write_pki_creates_all_seven_files() {
        let out = temp_out();
        let cfg = config_at(out.clone(), false);
        let pki = generate_pki(&cfg).unwrap();
        write_pki(&cfg, &pki).expect("écriture PKI");
        for p in OutputPaths::under(&out).all() {
            assert!(p.exists(), "fichier attendu absent: {}", p.display());
        }
    }

    #[test]
    fn write_pki_refuses_overwrite_without_force_and_touches_nothing() {
        let out = temp_out();
        let cfg = config_at(out.clone(), false);
        let pki = generate_pki(&cfg).unwrap();
        write_pki(&cfg, &pki).unwrap();

        // Marque un fichier avec un contenu sentinelle pour prouver qu'un 2e run SANS --force ne
        // le touche pas.
        let ca_path = OutputPaths::under(&out).ca_pem;
        std::fs::write(&ca_path, "SENTINEL").unwrap();

        let cfg2 = config_at(out.clone(), false);
        let pki2 = generate_pki(&cfg2).unwrap();
        let err = write_pki(&cfg2, &pki2).expect_err("un 2e run sans --force doit refuser");
        assert!(err.contains("--force"), "le refus doit mentionner --force: {err}");
        assert_eq!(
            std::fs::read_to_string(&ca_path).unwrap(),
            "SENTINEL",
            "aucun fichier ne doit être modifié sur un refus d'écrasement"
        );
    }

    #[test]
    fn write_pki_overwrites_with_force() {
        let out = temp_out();
        let cfg = config_at(out.clone(), false);
        let pki = generate_pki(&cfg).unwrap();
        write_pki(&cfg, &pki).unwrap();

        let ca_path = OutputPaths::under(&out).ca_pem;
        std::fs::write(&ca_path, "SENTINEL").unwrap();

        let cfg2 = config_at(out.clone(), true); // --force
        let pki2 = generate_pki(&cfg2).unwrap();
        write_pki(&cfg2, &pki2).expect("--force doit autoriser l'écrasement");
        assert_ne!(
            std::fs::read_to_string(&ca_path).unwrap(),
            "SENTINEL",
            "avec --force, le fichier doit être réécrit (plus la sentinelle)"
        );
        assert!(std::fs::read_to_string(&ca_path).unwrap().contains("BEGIN CERTIFICATE"));
    }
}
