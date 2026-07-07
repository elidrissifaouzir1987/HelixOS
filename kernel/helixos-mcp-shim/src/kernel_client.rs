#![forbid(unsafe_code)]
//! Client mTLS vers le noyau souverain. Présente le certificat client provisionné (identité
//! d'appelant), envoie l'intention `ProposeFilePatch{path, patch}` au **format de fil exact du
//! noyau** (une ligne JSON de `helixos_kernel::intention::Intention`, tag `kind`, snake_case),
//! puis lit la réponse (une ligne JSON : `{"plan_hash":"…"}` ou `{"error":"…"}`) et renvoie le
//! `plan_hash`.
//!
//! Le format de fil n'est PAS ré-inventé : le type `Intention` est partagé avec le noyau (crate
//! `helixos-kernel`, dépendance path), et la réponse est parsée par forme (`plan_hash` xor
//! `error`) car le type `WireResponse` du noyau est privé à son module `mtls`. Ce parsing par
//! forme est verrouillé par le test d'intégration bout-en-bout (source de vérité = le vrai
//! serveur du noyau).
//!
//! Le shim n'applique JAMAIS : il transmet une intention *propose* et rend le `plan_hash`.
//! L'application réelle passe par la page d'approbation (humain), hors de ce chemin.

use helixos_kernel::intention::Intention;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Erreur d'un aller-retour vers le noyau. Distingue les échecs de transport/config (le noyau est
/// injoignable, certs illisibles, TLS refusé) du refus fonctionnel renvoyé par le noyau lui-même
/// (`Kernel`, ex. « hors bail de portée »). Les deux se traduisent en une erreur d'OUTIL MCP
/// propre côté appelant — jamais un panic.
#[derive(Debug)]
pub enum KernelError {
    /// Chargement/parse des certificats ou de la clé (config d'exploitation invalide).
    Certs(String),
    /// Échec de connexion TCP ou de handshake TLS (noyau injoignable, cert client refusé, mauvais
    /// nom de serveur…).
    Transport(String),
    /// Le noyau a répondu, mais avec un refus fonctionnel (`{"error": …}`), p.ex. hors bail.
    KernelRefused(String),
    /// Réponse du noyau illisible / forme inattendue.
    Protocol(String),
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelError::Certs(m) => write!(f, "certificats mTLS invalides: {m}"),
            KernelError::Transport(m) => write!(f, "noyau injoignable/refus TLS: {m}"),
            KernelError::KernelRefused(m) => write!(f, "intention refusée par le noyau: {m}"),
            KernelError::Protocol(m) => write!(f, "réponse du noyau invalide: {m}"),
        }
    }
}
impl std::error::Error for KernelError {}

/// Matériel TLS client chargé depuis des fichiers PEM : CA de confiance (racines) + chaîne cliente
/// + clé privée. Séparé du transport pour être chargé une fois et réutilisé.
pub struct ClientTls {
    ca_roots: Arc<RootCertStore>,
    client_certs: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
}

impl ClientTls {
    /// Charge la CA, le certificat client et sa clé depuis trois fichiers PEM. `Err(Certs(..))`
    /// sur tout fichier absent/illisible/vide (config d'exploitation invalide) — jamais un panic.
    pub fn load(ca_path: &Path, client_cert_path: &Path, client_key_path: &Path) -> Result<Self, KernelError> {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| KernelError::Certs(format!("lecture CA {}: {e}", ca_path.display())))?;
        let mut ca_reader = &ca_pem[..];
        let mut ca_roots = RootCertStore::empty();
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut ca_reader) {
            let cert = cert.map_err(|e| KernelError::Certs(format!("CA PEM illisible: {e}")))?;
            ca_roots
                .add(cert)
                .map_err(|e| KernelError::Certs(format!("ajout CA aux racines: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(KernelError::Certs(format!(
                "aucun certificat CA trouvé dans {}",
                ca_path.display()
            )));
        }

        let cert_pem = std::fs::read(client_cert_path).map_err(|e| {
            KernelError::Certs(format!("lecture cert client {}: {e}", client_cert_path.display()))
        })?;
        let mut cert_reader = &cert_pem[..];
        let client_certs = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KernelError::Certs(format!("cert client PEM illisible: {e}")))?;
        if client_certs.is_empty() {
            return Err(KernelError::Certs(format!(
                "aucun certificat client dans {}",
                client_cert_path.display()
            )));
        }

        let key_pem = std::fs::read(client_key_path).map_err(|e| {
            KernelError::Certs(format!("lecture clé client {}: {e}", client_key_path.display()))
        })?;
        let mut key_reader = &key_pem[..];
        let client_key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| KernelError::Certs(format!("clé client PEM illisible: {e}")))?
            .ok_or_else(|| {
                KernelError::Certs(format!(
                    "aucune clé privée dans {}",
                    client_key_path.display()
                ))
            })?;

        Ok(Self { ca_roots: Arc::new(ca_roots), client_certs, client_key })
    }

    /// Construit depuis du matériel DER déjà en mémoire (utilisé par le harness de test, qui génère
    /// les certs via `rcgen` sans passer par le disque).
    pub fn from_der(
        ca_roots: Arc<RootCertStore>,
        client_certs: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> Self {
        Self { ca_roots, client_certs, client_key }
    }

    /// Assemble le `ClientConfig` rustls : fait confiance à `ca_roots` (la CA du noyau) et présente
    /// la chaîne cliente + clé (identité d'appelant, exigée par le `WebPkiClientVerifier` du noyau).
    fn build_config(&self) -> Result<Arc<ClientConfig>, KernelError> {
        let config = ClientConfig::builder()
            .with_root_certificates((*self.ca_roots).clone())
            .with_client_auth_cert(self.client_certs.clone(), self.client_key.clone_key())
            .map_err(|e| KernelError::Certs(format!("assemblage ClientConfig mTLS: {e}")))?;
        Ok(Arc::new(config))
    }
}

/// Envoie une intention `ProposeFilePatch{path, patch}` au noyau via mTLS et renvoie le
/// `plan_hash`. `kernel_addr` = `host:port` ; `server_name` = nom TLS attendu dans le cert serveur
/// (SNI + vérification de nom). N'applique jamais.
pub async fn propose_file_patch(
    tls: &ClientTls,
    kernel_addr: &str,
    server_name: &str,
    path: &str,
    patch: &str,
) -> Result<String, KernelError> {
    let intention = Intention::ProposeFilePatch { path: path.into(), patch: patch.to_string() };
    send_intention(tls, kernel_addr, server_name, &intention).await
}

/// Cœur du transport : connexion TCP → handshake TLS (avec cert client) → écrit l'intention en une
/// ligne JSON → lit une ligne de réponse → parse par forme. Séparé pour être exercé directement
/// par le test bout-en-bout avec une intention arbitraire.
pub async fn send_intention(
    tls: &ClientTls,
    kernel_addr: &str,
    server_name: &str,
    intention: &Intention,
) -> Result<String, KernelError> {
    let config = tls.build_config()?;
    let connector = TlsConnector::from(config);

    let server_name_owned = ServerName::try_from(server_name.to_string())
        .map_err(|e| KernelError::Transport(format!("nom de serveur TLS invalide '{server_name}': {e}")))?;

    let tcp = TcpStream::connect(kernel_addr)
        .await
        .map_err(|e| KernelError::Transport(format!("connexion TCP à {kernel_addr}: {e}")))?;
    let tls_stream = connector
        .connect(server_name_owned, tcp)
        .await
        .map_err(|e| KernelError::Transport(format!("handshake TLS avec {kernel_addr}: {e}")))?;

    let (reader, mut writer) = tokio::io::split(tls_stream);

    // Le format de fil du noyau : UNE ligne JSON de `Intention`, terminée par `\n`.
    let mut line = serde_json::to_string(intention)
        .map_err(|e| KernelError::Protocol(format!("sérialisation de l'intention: {e}")))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| KernelError::Transport(format!("écriture de l'intention: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| KernelError::Transport(format!("flush de l'intention: {e}")))?;

    let mut lines = BufReader::new(reader).lines();
    let response_line = lines
        .next_line()
        .await
        .map_err(|e| KernelError::Transport(format!("lecture de la réponse: {e}")))?
        .ok_or_else(|| KernelError::Protocol("connexion fermée sans réponse".into()))?;

    parse_plan_hash(&response_line)
}

/// Parse la réponse du noyau par FORME (le type `WireResponse` du noyau est privé) : `plan_hash`
/// présent ⟹ succès ; sinon `error` présent ⟹ refus fonctionnel. Toute autre forme ⟹ erreur de
/// protocole. Ce contrat est verrouillé par le test bout-en-bout contre le vrai serveur.
fn parse_plan_hash(response_line: &str) -> Result<String, KernelError> {
    let value: serde_json::Value = serde_json::from_str(response_line)
        .map_err(|e| KernelError::Protocol(format!("réponse non-JSON: {e} — reçu: {response_line}")))?;

    if let Some(hash) = value.get("plan_hash").and_then(|v| v.as_str()) {
        if hash.is_empty() {
            return Err(KernelError::Protocol("plan_hash vide dans la réponse du noyau".into()));
        }
        return Ok(hash.to_string());
    }
    if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
        return Err(KernelError::KernelRefused(err.to_string()));
    }
    Err(KernelError::Protocol(format!(
        "réponse du noyau sans 'plan_hash' ni 'error': {response_line}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix de revue D1a : l'entrée n'est PLUS codée en dur (`{"plan_hash":"abc123"}`), ce qui
    /// ré-encoderait aveuglément une forme de fil — potentiellement la MAUVAISE (c'est exactement le
    /// bug corrigé). On la régénère depuis un VRAI `serde_json::to_string` du `WireResponse` du
    /// noyau (type importé sous la feature `test-harness`), donc ce test suit automatiquement le
    /// format réel du noyau : si le noyau change sa forme de fil, l'octet testé ici change avec.
    #[test]
    fn parse_plan_hash_reads_success_shape() {
        let wire = serde_json::to_string(&helixos_kernel::mtls::WireResponse::PlanHash {
            plan_hash: "abc123".into(),
        })
        .unwrap();
        // Ceinture + bretelles : le fil du noyau DOIT être PLAT (`untagged`), sinon le shim ne peut
        // pas le parser par forme. On fige l'attente pour attraper une régression du format.
        assert_eq!(wire, r#"{"plan_hash":"abc123"}"#, "le fil de succès du noyau doit être PLAT");
        let hash = parse_plan_hash(&wire).unwrap();
        assert_eq!(hash, "abc123");
    }

    #[test]
    fn parse_plan_hash_maps_error_shape_to_kernel_refused() {
        // Idem : l'entrée d'erreur vient d'un vrai `WireResponse::Error` du noyau, pas d'un littéral.
        let wire = serde_json::to_string(&helixos_kernel::mtls::WireResponse::Error {
            error: "hors bail de portée (refus)".into(),
        })
        .unwrap();
        assert_eq!(wire, r#"{"error":"hors bail de portée (refus)"}"#, "le fil d'erreur du noyau doit être PLAT");
        let err = parse_plan_hash(&wire).unwrap_err();
        match err {
            KernelError::KernelRefused(m) => assert!(m.contains("hors bail")),
            other => panic!("attendu KernelRefused, obtenu {other:?}"),
        }
    }

    #[test]
    fn parse_plan_hash_rejects_empty_hash() {
        assert!(matches!(
            parse_plan_hash(r#"{"plan_hash":""}"#).unwrap_err(),
            KernelError::Protocol(_)
        ));
    }

    #[test]
    fn parse_plan_hash_rejects_unknown_shape() {
        assert!(matches!(
            parse_plan_hash(r#"{"weird":true}"#).unwrap_err(),
            KernelError::Protocol(_)
        ));
    }

    #[test]
    fn parse_plan_hash_rejects_non_json() {
        assert!(matches!(
            parse_plan_hash("not json at all").unwrap_err(),
            KernelError::Protocol(_)
        ));
    }
}
