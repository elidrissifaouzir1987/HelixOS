#![forbid(unsafe_code)]
//! B8 (SPIKE) : frontière mTLS minimale d'authentification d'appelant.
//!
//! Preuve du contrat de transport souverain : le noyau n'accepte que des appelants présentant
//! un certificat client valide (l'identité vient du cert, pas du réseau), et une intention
//! typée transportée sur ce canal authentifié atteint le `Kernel` et renvoie un `plan_hash`.
use helixos_kernel::intention::Intention;
use helixos_kernel::mtls::{connect_with_client_cert, connect_without_client_cert, spawn_test_server};
use std::path::PathBuf;

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn connection_without_client_cert_is_rejected() {   // test 3
    let lease_root = temp_dir("helix-mtls-lease");
    let state_dir = temp_dir("helix-mtls-state");
    let addr = spawn_test_server(lease_root, state_dir).await;

    // Un client TLS qui NE présente PAS de certificat client : le noyau exige un cert client
    // (contrôle primaire d'authentification), donc le handshake/échange doit échouer.
    let result = connect_without_client_cert(addr).await;
    assert!(result.is_err(), "un appelant sans certificat client doit être refusé");
}

#[tokio::test]
async fn authenticated_intention_returns_plan_hash() {
    let lease_root = temp_dir("helix-mtls-lease");
    let state_dir = temp_dir("helix-mtls-state");
    let note = lease_root.join("note.md");
    std::fs::write(&note, b"OLD").unwrap();
    let addr = spawn_test_server(lease_root, state_dir).await;

    let intention = Intention::ProposeFilePatch { path: note, patch: "NEW".into() };
    let plan_hash = connect_with_client_cert(addr, &intention)
        .await
        .expect("un appelant authentifié par certificat client doit obtenir un plan_hash");

    assert_eq!(plan_hash.len(), 64, "plan_hash doit être un sha256 hex (64 caractères)");
    assert!(plan_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn authenticated_intention_outside_lease_is_refused() {
    // Bout-en-bout du contrôle primaire (test 20) à travers la frontière mTLS : même authentifié
    // par certificat client valide, une intention hors bail de portée doit être refusée par le
    // noyau (le cert prouve l'IDENTITÉ, pas une autorisation élargie sur le contenu).
    let lease_root = temp_dir("helix-mtls-lease");
    let state_dir = temp_dir("helix-mtls-state");
    let addr = spawn_test_server(lease_root, state_dir).await;

    let outside = PathBuf::from("C:/Windows/system32/drivers/etc/hosts");
    let intention = Intention::ProposeFilePatch { path: outside, patch: "P".into() };
    let result = connect_with_client_cert(addr, &intention).await;
    assert!(result.is_err(), "une intention hors bail doit être refusée même authentifiée");
}
