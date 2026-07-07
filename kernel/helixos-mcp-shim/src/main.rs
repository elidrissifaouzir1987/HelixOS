#![forbid(unsafe_code)]
//! Point d'entrée du binaire `helixos-mcp-shim`. Charge la configuration (env), le matériel mTLS
//! client, puis sert le protocole MCP sur stdin/stdout. Toute la logique vit dans la bibliothèque
//! (`lib.rs` + modules) pour être testable ; `main` ne fait que câbler et rapporter les erreurs.

use helixos_mcp_shim::config::ShimConfig;
use helixos_mcp_shim::kernel_client::ClientTls;
use helixos_mcp_shim::{serve_stdio, MtlsToolExecutor};
use std::io::{self, BufReader};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Diagnostic sur stderr (stdout est réservé au flux JSON-RPC MCP). Jamais de panic.
            eprintln!("helixos-mcp-shim: erreur fatale: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = ShimConfig::from_env()?;
    let tls = ClientTls::load(&config.ca_path, &config.client_cert_path, &config.client_key_path)
        .map_err(|e| e.to_string())?;

    // Runtime tokio multi-thread pour les allers-retours mTLS. La boucle stdio (bloquante) tourne
    // sur le thread principal ; l'exécuteur d'outil `block_on` sur un HANDLE du runtime — sûr car
    // le thread principal n'est pas un worker de l'executor.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("construction du runtime tokio: {e}"))?;

    let executor = MtlsToolExecutor::new(tls, config, runtime.handle().clone());

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    serve_stdio(BufReader::new(stdin.lock()), &mut stdout, &executor)
        .map_err(|e| format!("boucle stdio MCP: {e}"))?;
    Ok(())
}
