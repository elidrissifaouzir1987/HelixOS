#![forbid(unsafe_code)]
//! Binaire de runtime `helixos-kernel` (bootstrap MVP-0) : mince pilote autour de
//! [`helixos_kernel::runtime`]. Il fait tourner SIMULTANÉMENT le serveur mTLS (appelants) ET la
//! micro-page HTTPS d'approbation, tous deux partageant le MÊME `Kernel` — un plan créé via mTLS
//! est donc approuvable sur la page.
//!
//! Toute la logique d'assemblage testable (parsing de config, chargement de la PKI, liaison +
//! exécution concurrente des deux serveurs) vit dans le module `runtime` de la lib ; ce fichier ne
//! porte que le parsing des args réels du processus + l'installation du Ctrl-C. Aucun `unwrap`/
//! panic dans le chemin de service : toute erreur est journalisée et convertie en code de sortie.
//!
//! Ce binaire n'embarque PAS `rcgen` : les certificats sont chargés depuis `--cert-dir` (produits
//! hors bande par `helixos-provision`).

use helixos_kernel::runtime::{self, ParseOutcome};
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match runtime::parse_config(std::env::args().skip(1), |k| std::env::var(k).ok()) {
        Ok(ParseOutcome::Help) => {
            print!("{}", runtime::usage());
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Run(config)) => config,
        Err(e) => {
            eprintln!("erreur: {e}\n\n{}", runtime::usage());
            return ExitCode::FAILURE;
        }
    };

    // Runtime tokio construit à la main (pas `#[tokio::main]`) pour garder un `main` renvoyant
    // `ExitCode` et propager proprement une erreur de construction du runtime.
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("erreur: construction du runtime tokio: {e}");
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(async move {
        let service = match runtime::bind(&config).await {
            Ok(service) => service,
            Err(e) => {
                eprintln!("erreur: {e}");
                return ExitCode::FAILURE;
            }
        };

        // Diagnostic de démarrage (stderr : ne pollue pas un éventuel usage de stdout).
        eprintln!("helixos-kernel: serveur mTLS sur https://{}", service.mtls_addr);
        eprintln!(
            "helixos-kernel: page d'approbation sur https://{} (origine {})",
            service.approval_addr, config.approval_origin
        );
        eprintln!(
            "helixos-kernel: noyau partagé — vault={:?}, task_id={}. Ctrl-C pour arrêter.",
            config.vault_roots, config.task_id
        );

        // Arrêt propre sur Ctrl-C. Si l'écoute du signal échoue, on ne panique pas : on log et on
        // laisse le service tourner jusqu'à l'arrêt d'un serveur (dégradation sûre, pas de crash).
        let shutdown = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => eprintln!("helixos-kernel: Ctrl-C reçu, arrêt."),
                Err(e) => {
                    eprintln!("helixos-kernel: écoute Ctrl-C indisponible ({e}) — arrêt sur fin de serveur.");
                    // Ne se résout jamais : laisse `select!` s'arrêter sur l'un des serveurs.
                    std::future::pending::<()>().await;
                }
            }
        };

        match service.serve(shutdown).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("erreur: {e}");
                ExitCode::FAILURE
            }
        }
    })
}
