#![forbid(unsafe_code)]
//! B8 (SPIKE) : frontière mTLS minimale d'authentification d'appelant.
//!
//! Preuve du contrat de transport souverain : le noyau n'accepte que des appelants présentant
//! un certificat client valide (l'identité vient du cert, pas du réseau), et une intention
//! typée transportée sur ce canal authentifié atteint le `Kernel` et renvoie un `plan_hash`.
use helixos_kernel::intention::Intention;
use helixos_kernel::mtls::{
    connect_with_client_cert, connect_with_foreign_client_cert, connect_without_client_cert,
    generate_test_certs, spawn_test_server,
};
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
    // (contrôle primaire d'authentification), donc la connexion doit être refusée.
    //
    // Discriminant (fix F1) : `connect_without_client_cert` renvoie `Ok(())` quand l'échange
    // applicatif ABOUTIT pleinement (= violation du contrôle primaire) et `Err` quand la
    // connexion est REJETÉE (= comportement correct). `is_err()==true` équivaut donc bien à
    // « le cert client était exigé » — avant ce fix la fonction renvoyait `Err` sur TOUS les
    // chemins (y compris quand le serveur avait répondu sans exiger de cert), rendant cette
    // assertion tautologique.
    //
    // Note (root cause creusée en corrigeant F1, voir doc de `connect_without_client_cert`) : en
    // TLS 1.3 le handshake côté CLIENT aboutit systématiquement même sans cert présenté (le
    // client envoie une chaîne `Certificate` vide, légale de son point de vue) — c'est le serveur
    // qui rejette ensuite via une alerte fatale `CertificateRequired`, consommée côté client au
    // premier I/O applicatif qui suit, pas pendant `connect()`. Le rejet se manifeste donc ici à
    // la LECTURE de la réponse, pas au handshake lui-même — les deux chemins sont gérés par la
    // fonction, celui-ci est le chemin réellement emprunté (vérifié empiriquement, déterministe).
    let result = connect_without_client_cert(addr).await;
    let err = result.expect_err("un appelant sans certificat client doit être refusé");

    // Renforcement : l'échec doit porter une ALERTE TLS FATALE explicite (le serveur a activement
    // signalé le refus au niveau protocole — `CertificateRequired`), pas une erreur applicative
    // incidente NI une simple fermeture anormale de connexion. Ce dernier cas est délibérément
    // EXCLU : creusé pendant le fix F1 (preuve par mutation, `allow_unauthenticated()` sur
    // `build_server_config`), un serveur qui n'exigerait PLUS de cert client produit aussi un
    // `Err` ici (le flux anonyme atteint `handle_authenticated_connection`, qui échoue sur son
    // propre invariant « pas de peer cert » et coupe la connexion sans `close_notify` propre) —
    // avec un message contenant « closed connection » mais SANS alerte `CertificateRequired`. Une
    // assertion qui accepterait ce message générique repasserait donc au vert sous ce mutant,
    // recréant une variante de la tautologie F1. `fatal alert`/`CertificateRequired` est le seul
    // signal qui distingue authentiquement « le serveur a exigé le cert et l'a fait savoir au
    // niveau TLS » de « le serveur a planté après avoir accepté une connexion qu'il n'aurait pas
    // dû accepter ».
    assert!(
        err.contains("fatal alert") || err.contains("CertificateRequired"),
        "l'échec doit porter une alerte TLS fatale explicite (cert client exigé), pas une simple \
         fermeture de connexion ni une erreur applicative incidente : {err}"
    );
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

    // Fix F9b : `is_err()` seul ne prouve pas QUE le refus vient du contrôle de bail — n'importe
    // quelle autre erreur (JSON, TLS, etc.) le ferait aussi passer. On vérifie donc que le
    // message d'erreur renvoyé par le noyau (transporté tel quel dans `WireResponse::Error` par
    // `handle_authenticated_connection`) indique bien explicitement un refus « hors bail ».
    let err = result.expect_err("une intention hors bail doit être refusée même authentifiée");
    assert!(
        err.contains("hors bail"),
        "le refus doit être signalé comme « hors bail de portée », pas une autre erreur incidente : {err}"
    );
}

#[tokio::test]
async fn authenticated_intention_with_other_ca_client_cert_is_rejected() {   // fix F9a
    // Certificat client structurellement valide (bonne forme, chaîne de signature interne
    // cohérente) mais émis par une CA totalement INDÉPENDANTE de celle du serveur — un scénario
    // distinct de « pas de certificat du tout » (test 3) : preuve que la vérification de chaîne
    // (`WebPkiClientVerifier` contre les `ca_roots` du serveur) rejette bien un cert dont
    // l'ÉMETTEUR n'est pas approuvé, pas seulement son absence.
    let lease_root = temp_dir("helix-mtls-lease");
    let state_dir = temp_dir("helix-mtls-state");
    let addr = spawn_test_server(lease_root, state_dir).await;

    // 2e CA + cert client indépendante, sans lien avec la CA enregistrée pour `addr`.
    let other_ca_certs = generate_test_certs();

    let intention = Intention::SearchFiles { query: "x".into() };
    let result = connect_with_foreign_client_cert(addr, &other_ca_certs.client, &intention).await;
    assert!(
        result.is_err(),
        "un certificat client signé par une AUTRE CA doit être rejeté au handshake, pas juste un cert absent"
    );
}
