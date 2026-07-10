//! Deterministic generator and drift checker for the public eligibility corpus.

#![forbid(unsafe_code)]

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../test-support/conformance_cases.rs"]
mod conformance_cases;
#[path = "../test-support/replay_claimant.rs"]
mod replay_claimant;

use conformance_cases::{canonical_bytes, execute_manifest, generated_manifest};
use helix_contracts::Sha256Digest;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const CASES_FILE: &str = "cases.json";
const OUTCOMES_FILE: &str = "expected-outcomes.json";

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 2
        || !matches!(
            arguments.first().map(String::as_str),
            Some("--write-fixtures" | "--check-fixtures")
        )
    {
        return Err(
            "usage: eligibility_corpus (--write-fixtures|--check-fixtures) <directory>".into(),
        );
    }

    let directory = PathBuf::from(&arguments[1]);
    let manifest = generated_manifest();
    let outcomes = execute_manifest(&manifest);
    let cases_bytes = canonical_bytes(&manifest);
    let outcomes_bytes = canonical_bytes(&outcomes);

    match arguments[0].as_str() {
        "--write-fixtures" => {
            fs::create_dir_all(&directory)?;
            fs::write(directory.join(CASES_FILE), &cases_bytes)?;
            fs::write(directory.join(OUTCOMES_FILE), &outcomes_bytes)?;
        }
        "--check-fixtures" => {
            check_exact(&directory.join(CASES_FILE), &cases_bytes)?;
            check_exact(&directory.join(OUTCOMES_FILE), &outcomes_bytes)?;
        }
        _ => unreachable!("argument validation keeps the mode closed"),
    }

    println!(
        "cases={} cases_sha256={} outcomes_sha256={}",
        manifest.cases.len(),
        Sha256Digest::digest(&cases_bytes),
        Sha256Digest::digest(&outcomes_bytes)
    );
    Ok(())
}

fn check_exact(path: &Path, expected: &[u8]) -> io::Result<()> {
    let actual = fs::read(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "generated fixture drift detected for {}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("eligibility corpus artifact")
        )))
    }
}
