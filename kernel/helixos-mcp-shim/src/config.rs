#![forbid(unsafe_code)]
//! Configuration du shim, entièrement pilotée par l'environnement (jamais en dur) : adresse du
//! noyau, origine d'approbation, chemins des certificats mTLS et nom de serveur TLS attendu.
//! Le conteneur Hermes lance `helixos-mcp-shim` avec ces variables d'environnement injectées par
//! le compose (voir `frontier/compose/docker-compose.yml`).

use std::path::PathBuf;

/// Nom des variables d'environnement de configuration. Regroupées pour un point de vérité unique
/// (docs compose + messages d'erreur).
pub mod env_keys {
    /// `host:port` du serveur mTLS du noyau (ex. `100.x.y.z:8443` ou `kernel.helix.ts.net:8443`).
    pub const KERNEL_ADDR: &str = "HELIX_KERNEL_ADDR";
    /// Origine (schéma+hôte[:port]) de la page d'approbation servie par le noyau, sans slash final
    /// (ex. `https://helix.tailnet.ts.net`). L'`approval_url` en découle : `<origine>/op/<hash>`.
    pub const APPROVAL_ORIGIN: &str = "HELIX_APPROVAL_ORIGIN";
    /// Chemin du bundle PEM de la CA de confiance (celle qui a signé le cert serveur du noyau).
    pub const CA_PATH: &str = "HELIX_MTLS_CA";
    /// Chemin du certificat client PEM que le shim présente au noyau (son identité d'appelant).
    pub const CLIENT_CERT_PATH: &str = "HELIX_MTLS_CLIENT_CERT";
    /// Chemin de la clé privée PEM du certificat client (PKCS#8 ou RSA/SEC1).
    pub const CLIENT_KEY_PATH: &str = "HELIX_MTLS_CLIENT_KEY";
    /// Nom de serveur TLS attendu dans le cert du noyau (SNI + vérification de nom). Défaut :
    /// `localhost` (harnais/bureau). En prod = nom MagicDNS du noyau.
    pub const SERVER_NAME: &str = "HELIX_KERNEL_SERVER_NAME";
}

/// Configuration résolue et validée du shim.
#[derive(Debug, Clone)]
pub struct ShimConfig {
    /// `host:port` du serveur mTLS du noyau, tel quel (résolu par `tokio::net::lookup_host`).
    pub kernel_addr: String,
    /// Origine d'approbation sans slash final.
    pub approval_origin: String,
    /// CA de confiance (PEM).
    pub ca_path: PathBuf,
    /// Certificat client (PEM).
    pub client_cert_path: PathBuf,
    /// Clé privée du certificat client (PEM).
    pub client_key_path: PathBuf,
    /// Nom de serveur TLS attendu (vérification de nom + SNI).
    pub server_name: String,
}

impl ShimConfig {
    /// Charge la configuration depuis l'environnement du processus. `Err` liste précisément la
    /// première variable manquante (message actionnable pour l'exploitant), jamais un panic.
    pub fn from_env() -> Result<Self, String> {
        Self::from_getter(|k| std::env::var(k).ok())
    }

    /// Variante testable : `getter(key) -> Option<String>` remplace l'accès direct à
    /// l'environnement du processus (les tests injectent une map sans toucher aux vraies
    /// variables d'environnement, qui sont un état global partagé et fragile en test parallèle).
    pub fn from_getter(getter: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let require = |key: &str| -> Result<String, String> {
            getter(key)
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("variable d'environnement requise manquante ou vide: {key}"))
        };

        let kernel_addr = require(env_keys::KERNEL_ADDR)?;
        // Normalise l'origine : retire un éventuel slash final pour que `<origine>/op/<hash>` ne
        // produise jamais un double slash.
        let approval_origin = require(env_keys::APPROVAL_ORIGIN)?
            .trim_end_matches('/')
            .to_string();
        let ca_path = PathBuf::from(require(env_keys::CA_PATH)?);
        let client_cert_path = PathBuf::from(require(env_keys::CLIENT_CERT_PATH)?);
        let client_key_path = PathBuf::from(require(env_keys::CLIENT_KEY_PATH)?);
        let server_name = getter(env_keys::SERVER_NAME)
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "localhost".to_string());

        Ok(Self { kernel_addr, approval_origin, ca_path, client_cert_path, client_key_path, server_name })
    }

    /// Construit l'URL de la carte d'approbation pour un `plan_hash` donné :
    /// `<approval_origin>/op/<plan_hash>`.
    pub fn approval_url(&self, plan_hash: &str) -> String {
        format!("{}/op/{}", self.approval_origin, plan_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn getter(map: HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |k| map.get(k).map(|s| s.to_string())
    }

    fn full_map() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (env_keys::KERNEL_ADDR, "127.0.0.1:8443"),
            (env_keys::APPROVAL_ORIGIN, "https://helix.example.ts.net/"),
            (env_keys::CA_PATH, "/etc/helix/ca.pem"),
            (env_keys::CLIENT_CERT_PATH, "/etc/helix/client.pem"),
            (env_keys::CLIENT_KEY_PATH, "/etc/helix/client.key"),
        ])
    }

    #[test]
    fn loads_all_fields_and_defaults_server_name() {
        let cfg = ShimConfig::from_getter(getter(full_map())).unwrap();
        assert_eq!(cfg.kernel_addr, "127.0.0.1:8443");
        // Le slash final a été retiré.
        assert_eq!(cfg.approval_origin, "https://helix.example.ts.net");
        assert_eq!(cfg.server_name, "localhost");
    }

    #[test]
    fn approval_url_is_origin_slash_op_slash_hash() {
        let cfg = ShimConfig::from_getter(getter(full_map())).unwrap();
        assert_eq!(
            cfg.approval_url("deadbeef"),
            "https://helix.example.ts.net/op/deadbeef"
        );
    }

    #[test]
    fn missing_kernel_addr_is_an_error() {
        let mut map = full_map();
        map.remove(env_keys::KERNEL_ADDR);
        let err = ShimConfig::from_getter(getter(map)).unwrap_err();
        assert!(err.contains(env_keys::KERNEL_ADDR));
    }

    #[test]
    fn explicit_server_name_overrides_default() {
        let mut map = full_map();
        map.insert(env_keys::SERVER_NAME, "kernel.helix.ts.net");
        let cfg = ShimConfig::from_getter(getter(map)).unwrap();
        assert_eq!(cfg.server_name, "kernel.helix.ts.net");
    }
}
