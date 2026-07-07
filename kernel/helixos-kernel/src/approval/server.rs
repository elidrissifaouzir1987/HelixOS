#![forbid(unsafe_code)]
//! C2 (SPIKE) : micro-page HTTPS d'approbation, sur une origine **distincte** du port mTLS.
//!
//! Contrat prouvé ici (voir `docs/superpowers/plans/2026-07-06-helixos-mvp0.md`, Task C2) :
//! `GET /op/{hash}` rend la carte d'approbation (§4, `approval::card::Card`) d'un plan encore en
//! vol ; `POST /op/{hash}/approve` déclenche `Kernel::apply` pour un plan **L1** (tap) mais
//! refuse tout plan **L2** sans jamais l'appliquer (passkey requise, WebAuthn = C3, hors
//! périmètre ici) ; `GET /ops` liste les opérations en vol pour un tableau de bord minimal.
//! Chaque réponse porte `Content-Security-Policy: frame-ancestors 'none'` et
//! `X-Frame-Options: DENY` — cette page ne doit jamais pouvoir être embarquée dans un iframe
//! d'une autre origine (surface d'approbation hors webui, Global Constraints).
//!
//! ## Écarts vérifiés vs l'énoncé du plan (spike axum/axum-server)
//!
//! 1. **Segments de route `{hash}`, pas `:hash`.** axum 0.8 valide activement les chemins de
//!    route au moment de `Router::route` et **panique** si un segment commence par `:`, avec un
//!    message explicite renvoyant vers la nouvelle syntaxe `{capture}` (`matchit`/axum-routing
//!    v0.7+ ; vérifié en lisant `axum-0.8.9/src/routing/path_router.rs::validate_v07_paths`).
//!    Le `:hash` de l'énoncé était donc l'ancienne syntaxe (axum ≤0.6) — adapté ici à l'API réelle.
//! 2. **`serve_https` prend un `std::net::TcpListener` déjà lié**, pas un `SocketAddr` littéral.
//!    Choix délibéré (pas une contrainte d'API) : lier le port AVANT de démarrer la tâche serveur
//!    permet à l'appelant (tests, futur `main.rs`) de connaître l'adresse effective (utile pour
//!    `127.0.0.1:0`, port choisi par l'OS) sans registre de coordination externe — le même besoin
//!    que l'ancien plan avait résolu pour `mtls::spawn_test_server` via un registre process-global
//!    (`test_cert_registry`) ; ici un simple listener pré-bindé suffit, sans registre.
//! 3. **En-têtes de sécurité posés par middleware `axum::middleware::map_response`**, pas par un
//!    en-tête recopié dans chaque handler : plus sûr par construction (impossible d'oublier
//!    l'en-tête sur une route future ou sur le 404 de fallback, qui passe aussi par cette couche).
use crate::approval::card::Card;
use crate::pipeline::SharedKernel;
use crate::policy::RiskLevel;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

/// Assemble le router de la surface d'approbation. `shared` est le [`SharedKernel`] partagé avec
/// (plus tard) le serveur mTLS — cette page ne construit jamais son propre `Kernel` isolé.
pub fn build_router(shared: SharedKernel) -> Router {
    Router::new()
        .route("/op/{hash}", get(get_operation))
        .route("/op/{hash}/approve", post(approve_operation))
        .route("/ops", get(list_in_flight))
        .with_state(shared)
        // Appliqué à TOUTES les réponses de ce router, y compris le 404 de fallback par défaut
        // d'axum pour une route non déclarée — la surface d'approbation entière reste anti-embed.
        .layer(axum::middleware::map_response(add_security_headers))
}

/// Pose `Content-Security-Policy: frame-ancestors 'none'` et `X-Frame-Options: DENY` sur chaque
/// réponse sortante de ce router (Global Constraints : approbation hors webui, jamais embarquable
/// dans un iframe d'une autre origine).
async fn add_security_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

/// `GET /op/{hash}` : rend la carte d'approbation (§4) d'un plan encore connu du noyau. Un plan
/// est rendu qu'il soit en vol, expiré ou déjà consommé (l'utilisateur doit pouvoir voir *ce
/// qu'il a approuvé/refusé* même après coup) — seule l'absence totale du hash produit 404 ;
/// `approve_operation` ci-dessous est le point qui refuse réellement une action sur un plan
/// expiré/consommé.
async fn get_operation(State(shared): State<SharedKernel>, Path(hash): Path<String>) -> Response {
    let kernel = shared.lock().await;
    match kernel.get_plan(&hash) {
        // MVP-0 : `Plan` ne porte pas encore les paramètres `tainted`/`unusual` de `Card`
        // (calculés au moment de `plan_intention`, jamais persistés sur le plan lui-même) — la
        // carte affiche donc fidèlement le risque réel (`plan.risk`, déjà figé par `policy`) mais
        // pas le luxe du bandeau taint. La DÉCISION de sécurité (L1 tap / L2 refus, ci-dessous)
        // reste basée sur `plan.risk`, jamais sur cet affichage — aucune faille, juste un
        // affichage moins riche que ce que `Card` peut exprimer.
        Some(plan) => {
            let card = Card::from_plan(&plan, None, false);
            (
                StatusCode::OK,
                [("content-type", "text/html; charset=utf-8")],
                card.render_html(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "plan inconnu").into_response(),
    }
}

/// `POST /op/{hash}/approve` : L1 = tap -> applique ; L2 = refus (passkey requise, C3) ; plan
/// inconnu -> 404 ; plan déjà consommé/expiré -> 409 (une erreur de conflit d'état, pas une
/// absence). `apply` verrouille le même [`SharedKernel`] que `get_operation`/`list_in_flight` —
/// jamais un noyau indépendant.
async fn approve_operation(
    State(shared): State<SharedKernel>,
    Path(hash): Path<String>,
) -> Response {
    let mut kernel = shared.lock().await;
    let Some(plan) = kernel.get_plan(&hash) else {
        return (StatusCode::NOT_FOUND, "plan inconnu").into_response();
    };

    if plan.risk == RiskLevel::L2 {
        // Refus explicite AVANT tout appel à `apply` : un plan L2 ne doit jamais être appliqué
        // par un simple tap, quelle que soit la suite (WebAuthn/passkey = C3, hors périmètre ici).
        return (
            StatusCode::FORBIDDEN,
            "L2 — passkey requise (WebAuthn à venir, C3)",
        )
            .into_response();
    }

    match kernel.apply(&hash) {
        Ok(outcome) => (
            StatusCode::OK,
            Json(ApproveResponse {
                plan_hash: hash,
                rollback_id: outcome.rollback_id,
            }),
        )
            .into_response(),
        // `apply` échoue encore ici pour un plan déjà consommé (course entre deux requêtes
        // concurrentes ayant chacune lu le même `get_plan` avant que l'une des deux n'applique)
        // ou expiré/TOCTOU entre le `get_plan` ci-dessus et cet `apply` — toujours un conflit
        // d'état, jamais une absence : 409, pas 404/500.
        Err(message) => (StatusCode::CONFLICT, message).into_response(),
    }
}

/// `GET /ops` : liste JSON des opérations en vol (`Kernel::in_flight`) — hash, cible, risque.
async fn list_in_flight(State(shared): State<SharedKernel>) -> Response {
    let kernel = shared.lock().await;
    let ops: Vec<OpSummary> = kernel
        .in_flight()
        .iter()
        .map(|plan| OpSummary {
            plan_hash: plan.plan_hash.clone(),
            target: plan.target.display().to_string(),
            risk: format!("{:?}", plan.risk),
        })
        .collect();
    Json(ops).into_response()
}

#[derive(Serialize)]
struct ApproveResponse {
    plan_hash: String,
    rollback_id: String,
}

#[derive(Serialize)]
struct OpSummary {
    plan_hash: String,
    target: String,
    risk: String,
}

// Fix (cohérent avec F4 hérité de B8) : le harness TLS de ce module (génération de certif via
// `rcgen`, binding HTTPS de test) vit sous la feature `test-harness` — jamais compilé dans le
// binaire de PRODUCTION. `serve_https` elle-même (ci-dessous) reste NON gatée : c'est la future
// API de production (le certificat/la clé sont un input de config, pas générés par le noyau), elle
// ne dépend d'aucun symbole de `rcgen`.

/// (SPIKE) Sert `router` en HTTPS sur `listener` (déjà lié — voir écart n°2 ci-dessus), via
/// `axum-server` + rustls, avec un certificat fourni en PEM (cert + clé). Boucle tant que le
/// serveur tourne (comme `axum_server::Server::serve`) ; API de PRODUCTION — le certificat/la clé
/// sont un input de config externe (`tailscale cert` pour le nom MagicDNS en usage réel, cf. plan
/// Phase E), jamais générés ici.
pub async fn serve_https(
    listener: std::net::TcpListener,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    router: Router,
) -> std::io::Result<()> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
    axum_server::from_tcp(listener)?
        .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(config))
        .serve(router.into_make_service())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_response_serializes_plan_hash_and_rollback_id() {
        let body = ApproveResponse { plan_hash: "h".into(), rollback_id: "r".into() };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"plan_hash\":\"h\""));
        assert!(json.contains("\"rollback_id\":\"r\""));
    }

    #[test]
    fn op_summary_serializes_expected_fields() {
        let summary = OpSummary { plan_hash: "h".into(), target: "t".into(), risk: "L1".into() };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"plan_hash\":\"h\""));
        assert!(json.contains("\"target\":\"t\""));
        assert!(json.contains("\"risk\":\"L1\""));
    }
}
