#![forbid(unsafe_code)]
//! C2 (SPIKE) : micro-page HTTPS d'approbation sur origine distincte.
//!
//! Preuve du contrat de surface d'approbation hors webui : `GET /op/{hash}` rend la carte
//! d'approbation (§4) avec les en-têtes anti-embedding (`frame-ancestors 'none'`,
//! `X-Frame-Options: DENY`) sur CHAQUE réponse ; `POST /op/{hash}/approve` applique un plan L1
//! (tap) mais refuse un plan L2 (passkey requise, WebAuthn = C3, hors périmètre ici) ; `GET /ops`
//! liste les opérations en vol. La logique du router est exercée directement via
//! `tower::ServiceExt::oneshot` (pas besoin de TLS réel pour ces routes) ; un test séparé,
//! gated par la feature `test-harness`, prouve le binding TLS sur une origine distincte.
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use helixos_kernel::approval::server::build_router;
use helixos_kernel::intention::Intention;
use helixos_kernel::pipeline::{Kernel, SharedKernel};
use helixos_kernel::scope::ScopeLease;
use http_body_util::BodyExt;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Prépare un vrai tempdir vault + note + `Kernel` (vrai état sur disque, pas de mock) et
/// l'enveloppe dans le `SharedKernel` attendu par `build_router`.
fn kernel_with_note(content: &[u8]) -> (SharedKernel, PathBuf) {
    let vault = temp_dir("helix-approval-vault");
    let state_dir = temp_dir("helix-approval-state");
    let target = vault.join("note.md");
    std::fs::write(&target, content).unwrap();
    let lease = ScopeLease { task_id: "t1".into(), roots: vec![vault] };
    let kernel = Kernel::new(state_dir, lease).unwrap();
    (Arc::new(tokio::sync::Mutex::new(kernel)), target)
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Vérifie la CSP durcie (revue C2 : `default-src 'none'` rend tout script inerte par
/// construction, en plus de `frame-ancestors 'none'` déjà prouvé) et `X-Frame-Options: DENY`,
/// posés par le middleware `add_security_headers` sur TOUTE réponse de ce router — y compris les
/// réponses de refus (403/409/405), pas seulement 200/404 (durcissement de couverture, revue C2) :
/// le middleware étant appliqué une seule fois via `.layer(...)` sur le router entier, il n'existe
/// aucun chemin de réponse qui y échappe, mais on le prouve explicitement sur chaque code observé
/// plutôt que de le supposer.
fn assert_anti_embedding_headers(response: &axum::response::Response) {
    let headers = response.headers();
    let csp = headers
        .get("content-security-policy")
        .expect("CSP doit être présente sur toute réponse de la surface d'approbation")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'none'"),
        "CSP doit contenir default-src 'none' (script inerte par construction): {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP doit contenir frame-ancestors 'none': {csp}"
    );
    assert_eq!(
        headers.get("x-frame-options"),
        Some(&HeaderValue::from_static("DENY")),
        "X-Frame-Options: DENY doit être présent sur toute réponse de la surface d'approbation"
    );
}

#[tokio::test]
async fn get_existing_l1_plan_renders_card_with_security_headers() {
    let (shared, target) = kernel_with_note(b"OLD");
    let plan_hash = {
        let mut kernel = shared.lock().await;
        let plan = kernel
            .plan_intention(
                "t1",
                "hermes",
                Intention::ProposeFilePatch { path: target, patch: "NEW".into() },
                false, // non tainté -> L1 (ProposeFilePatch de base)
            )
            .unwrap();
        assert_eq!(plan.risk, helixos_kernel::policy::RiskLevel::L1, "précondition du test : plan L1");
        plan.plan_hash
    };

    let router = build_router(shared);
    let request = Request::builder()
        .uri(format!("/op/{plan_hash}"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_anti_embedding_headers(&response);
    let body = body_string(response).await;
    for label in ["QUOI", "OÙ", "RISQUE", "POURQUOI", "INHABITUEL"] {
        assert!(body.contains(label), "section {label} absente de la carte rendue: {body}");
    }
    assert!(body.contains(&plan_hash), "le hash du plan doit être visible dans la carte");
}

#[tokio::test]
async fn get_unknown_plan_is_404_with_security_headers() {
    let (shared, _target) = kernel_with_note(b"OLD");
    let router = build_router(shared);
    let request = Request::builder().uri("/op/does-not-exist").body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_anti_embedding_headers(&response);
}

#[tokio::test]
async fn approve_l1_plan_applies_patch_to_real_file() {
    let (shared, target) = kernel_with_note(b"OLD");
    let plan_hash = {
        let mut kernel = shared.lock().await;
        let plan = kernel
            .plan_intention(
                "t1",
                "hermes",
                Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() },
                false,
            )
            .unwrap();
        plan.plan_hash
    };

    let router = build_router(shared.clone());
    let request = Request::builder()
        .method("POST")
        .uri(format!("/op/{plan_hash}/approve"))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK, "un plan L1 approuvé doit être appliqué (200)");
    // Le fichier cible est réellement patché — relit le fichier sur disque, pas seulement le
    // code de statut HTTP (qui pourrait mentir sur un chemin de test court-circuité).
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"NEW",
        "le fichier cible doit être réellement patché après approbation L1"
    );

    // Usage unique : ré-approuver le même plan_hash doit maintenant être refusé (409) — preuve
    // supplémentaire que le 1er appel a bien traversé le vrai `Kernel::apply` (pas un stub).
    // `Router: Clone` (Arc interne, cf. axum::routing::Router) : le clone partage le même state
    // (`SharedKernel`), donc voit bien l'effet du 1er appel.
    let replay_request = Request::builder()
        .method("POST")
        .uri(format!("/op/{plan_hash}/approve"))
        .body(Body::empty())
        .unwrap();
    let replay_response = router.oneshot(replay_request).await.unwrap();
    assert_eq!(replay_response.status(), StatusCode::CONFLICT, "rejeu du même plan_hash doit être refusé");
}

#[tokio::test]
async fn approve_l1_plan_writes_audit_record() {
    let vault = temp_dir("helix-approval-vault");
    let state_dir = temp_dir("helix-approval-state");
    let target = vault.join("note.md");
    std::fs::write(&target, b"OLD").unwrap();
    let lease = ScopeLease { task_id: "t1".into(), roots: vec![vault] };
    let kernel = Kernel::new(state_dir.clone(), lease).unwrap();
    let shared: SharedKernel = Arc::new(tokio::sync::Mutex::new(kernel));

    let plan_hash = {
        let mut k = shared.lock().await;
        let plan = k
            .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false)
            .unwrap();
        plan.plan_hash
    };

    let router = build_router(shared);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/op/{plan_hash}/approve"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let audit_content = std::fs::read_to_string(state_dir.join("audit.jsonl"))
        .expect("audit.jsonl doit exister après une approbation L1 appliquée");
    assert!(audit_content.contains(&plan_hash), "l'audit doit référencer le plan_hash appliqué");
    assert!(audit_content.contains("apply_file_patch"));
}

#[tokio::test]
async fn approve_l2_plan_is_forbidden_and_file_unchanged() {
    let (shared, target) = kernel_with_note(b"OLD");
    let plan_hash = {
        let mut kernel = shared.lock().await;
        // L2 : un `ProposeFilePatch` (base L1) sous taint escalade d'un cran -> L2 (policy::classify).
        // C'est le seul chemin de plan_intention capable de produire un plan L2 planifiable en
        // MVP-0 (ReadFile, seul autre générateur de L2, n'est plus planifiable — fix F2).
        let plan = kernel
            .plan_intention(
                "t1",
                "hermes",
                Intention::ProposeFilePatch { path: target.clone(), patch: "SHOULD-NOT-APPLY".into() },
                true, // tainted -> L1 de base escalade en L2
            )
            .unwrap();
        assert_eq!(plan.risk, helixos_kernel::policy::RiskLevel::L2, "précondition du test : plan L2");
        plan.plan_hash
    };

    let router = build_router(shared);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/op/{plan_hash}/approve"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "un plan L2 doit être refusé (403), pas appliqué silencieusement");
    assert_anti_embedding_headers(&response);
    let body = body_string(response).await;
    assert!(
        body.to_lowercase().contains("passkey") || body.to_lowercase().contains("l2"),
        "le message de refus doit expliquer qu'une passkey L2 est requise (WebAuthn = C3): {body}"
    );

    assert_eq!(std::fs::read(&target).unwrap(), b"OLD", "un plan L2 refusé ne doit JAMAIS toucher le fichier cible");
}

#[tokio::test]
async fn approve_unknown_plan_is_404() {
    let (shared, _target) = kernel_with_note(b"OLD");
    let router = build_router(shared);
    let request = Request::builder()
        .method("POST")
        .uri("/op/does-not-exist/approve")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_already_consumed_plan_is_conflict() {
    let (shared, target) = kernel_with_note(b"OLD");
    let plan_hash = {
        let mut kernel = shared.lock().await;
        let plan = kernel
            .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target, patch: "NEW".into() }, false)
            .unwrap();
        let hash = plan.plan_hash.clone();
        kernel.apply(&hash).unwrap(); // consommé hors router, directement via le noyau
        hash
    };

    let router = build_router(shared);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/op/{plan_hash}/approve"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "un plan déjà consommé doit renvoyer 409, pas être ré-appliqué silencieusement"
    );
    assert_anti_embedding_headers(&response);
}

#[tokio::test]
async fn disallowed_method_on_known_route_is_405_with_security_headers() {
    // Durcissement de couverture (revue C2) : preuve que le middleware d'en-têtes de sécurité
    // couvre TOUTES les réponses, y compris un refus de méthode (405) sur un path par ailleurs
    // connu du router — pas seulement les réponses "métier" (200/403/404/409). `/op/{hash}` n'a
    // qu'un handler `get` ; un `POST` dessus doit être rejeté par le routeur lui-même (405), avant
    // même d'atteindre un handler applicatif — et porter quand même la CSP + X-Frame-Options.
    let (shared, _target) = kernel_with_note(b"OLD");
    let router = build_router(shared);
    let request = Request::builder()
        .method("POST")
        .uri("/op/does-not-exist")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "un POST sur /op/{{hash}} (route GET uniquement) doit être 405"
    );
    assert_anti_embedding_headers(&response);
}

#[tokio::test]
async fn ops_lists_in_flight_plan() {
    let (shared, target) = kernel_with_note(b"OLD");
    let plan_hash = {
        let mut kernel = shared.lock().await;
        let plan = kernel
            .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false)
            .unwrap();
        plan.plan_hash
    };

    let router = build_router(shared);
    let request = Request::builder().uri("/ops").body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_anti_embedding_headers(&response);
    let body = body_string(response).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("la liste /ops doit être un JSON valide");
    let ops = parsed.as_array().expect("/ops doit renvoyer un tableau JSON");
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["plan_hash"], plan_hash);
    assert_eq!(ops[0]["target"], target.display().to_string());
    assert_eq!(ops[0]["risk"], "L1");
}

#[tokio::test]
async fn ops_excludes_consumed_plan() {
    let (shared, target) = kernel_with_note(b"OLD");
    {
        let mut kernel = shared.lock().await;
        let plan = kernel
            .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target, patch: "NEW".into() }, false)
            .unwrap();
        kernel.apply(&plan.plan_hash).unwrap();
    }

    let router = build_router(shared);
    let request = Request::builder().uri("/ops").body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    let body = body_string(response).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0, "un plan consommé ne doit plus apparaître dans /ops");
}

// --- SPIKE TLS : preuve du binding HTTPS sur origine distincte ---
//
// Gated par `test-harness` (rcgen n'est jamais tiré dans le binaire de production, voir Cargo.toml
// / fix F4 hérité de B8). Démarre `serve_https` sur `127.0.0.1:0` avec un certificat rcgen
// éphémère, puis un client TLS (fabriqué à la main via `tokio-rustls`, cohérent avec le pattern
// déjà utilisé par `mtls::test_harness` — pas de dépendance HTTP-client supplémentaire) fait un
// GET /op/{hash} en HTTPS et doit recevoir 200. Preuve que le serveur d'approbation bind
// réellement TLS sur une origine séparée du port mTLS, pas seulement un stub HTTP.
#[cfg(feature = "test-harness")]
mod tls_spike {
    use super::*;
    use helixos_kernel::approval::server::serve_https;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn approval_page_is_served_over_https_on_distinct_origin() {
        let (shared, target) = kernel_with_note(b"OLD");
        let plan_hash = {
            let mut kernel = shared.lock().await;
            let plan = kernel
                .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target, patch: "NEW".into() }, false)
                .unwrap();
            plan.plan_hash
        };

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("génération d'un certificat de test rcgen pour le spike TLS");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let router = build_router(shared);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind du listener TLS de test");
        listener.set_nonblocking(true).expect("listener non bloquant");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = serve_https(listener, cert_pem.into_bytes(), key_pem.into_bytes(), router).await;
        });

        // Laisse le serveur démarrer effectivement avant de s'y connecter (pas d'accept() bloquant
        // exposé à ce niveau — un petit retry est plus robuste qu'un sleep fixe).
        let mut root_store = RootCertStore::empty();
        // Client volontairement permissif sur la vérification du cert serveur : le spike prouve le
        // BINDING TLS (le handshake aboutit, la couche applicative répond), pas la chaîne de
        // confiance PKI (hors périmètre C2 — le certif MagicDNS réel est un input de config future,
        // cf. plan). `RootCertStore` vide + vérificateur "accepte tout" dédié au test uniquement.
        let verifier = Arc::new(NoServerVerification);
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let _ = &mut root_store; // conservé pour lisibilité de l'intention, non utilisé (verifier custom)
        let connector = TlsConnector::from(Arc::new(client_config));

        let mut last_err = None;
        let mut response_line = None;
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(tcp) => {
                    let server_name = ServerName::try_from("localhost").unwrap();
                    match connector.connect(server_name, tcp).await {
                        Ok(tls) => {
                            let (reader, mut writer) = tokio::io::split(tls);
                            let req = format!(
                                "GET /op/{plan_hash} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                            );
                            if writer.write_all(req.as_bytes()).await.is_ok() && writer.flush().await.is_ok() {
                                let mut lines = BufReader::new(reader).lines();
                                if let Ok(Some(line)) = lines.next_line().await {
                                    response_line = Some(line);
                                    break;
                                }
                            }
                        }
                        Err(e) => last_err = Some(format!("handshake TLS: {e}")),
                    }
                }
                Err(e) => last_err = Some(format!("connexion TCP: {e}")),
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let status_line = response_line.unwrap_or_else(|| {
            panic!("SPIKE TLS ÉCHOUÉ après 50 tentatives (2.5s) : {last_err:?}")
        });
        assert!(
            status_line.contains("200"),
            "le GET /op/{{hash}} en HTTPS doit renvoyer 200 sur le binding TLS d'origine distincte: {status_line}"
        );
    }

    /// Vérificateur de certificat serveur permissif, réservé au spike TLS ci-dessus : ce test
    /// prouve que `serve_https` bind réellement TLS et sert le router applicatif dessus — pas la
    /// validité PKI d'un certificat MagicDNS de production (hors périmètre C2, cf. note du plan).
    #[derive(Debug)]
    struct NoServerVerification;

    impl rustls::client::danger::ServerCertVerifier for NoServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .expect("crypto provider process-défaut déjà installé (aws-lc-rs, voir mtls.rs)")
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
