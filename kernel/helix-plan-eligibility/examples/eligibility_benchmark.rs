//! Release evidence benchmark for the portable plan-eligibility leaf.
//!
//! This measures one complete evaluator call plus the deterministic test claimant. It
//! is local performance evidence only, never production replay durability or authority.

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../test-support/replay_claimant.rs"]
mod replay_claimant;

use common::{authentic_plan, coherent_ready_input, EligibilityFixture};
use helix_contracts::{AuthenticPlanEnvelopeV1, Sha256Digest, MAX_SAFE_U64};
use helix_plan_eligibility::{EligibilityContextV1, ReadyEligibilityContextV1};
use replay_claimant::DeterministicReplayClaimant;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const EVIDENCE_SCHEMA: &str = "helixos.plan-eligibility-benchmark/1";
const ACCEPTANCE_ID: &str = "PLAN-002";
const CORPUS_SCHEMA: &str = "helixos.plan-eligibility-summary/1";
const PUBLIC_CASE_ID: &str = "eligible-coherent";
const PINNED_EXPECTED_OUTCOMES_SHA256: &str =
    "258fcd002c335a1f25070e593ae97eb7472b2fe55342134058e2e4e470af7bbb";
const PINNED_RUST_RELEASE: &str = "1.96.1";
const DEFAULT_WARMUPS: usize = 1_000;
const DEFAULT_ITERATIONS: usize = 10_000;
const P95_LIMIT_NS: u64 = 1_000_000;

#[derive(Debug)]
struct Options {
    evidence: PathBuf,
    warmups: usize,
    iterations: usize,
}

#[derive(Serialize)]
struct BenchmarkEvidence {
    schema: &'static str,
    acceptance_id: &'static str,
    corpus: CorpusEvidence,
    environment: EnvironmentEvidence,
    workload: WorkloadEvidence,
    results: ResultEvidence,
    limitations: [&'static str; 3],
}

#[derive(Serialize)]
struct CorpusEvidence {
    schema: &'static str,
    expected_outcomes_bytes: usize,
    expected_outcomes_sha256: String,
    public_case_id: &'static str,
}

#[derive(Serialize)]
struct EnvironmentEvidence {
    hardware: String,
    available_parallelism: usize,
    os: &'static str,
    arch: &'static str,
    build_profile: &'static str,
    rustc_version_line: String,
    rustc_release: String,
    rustc_commit_hash: String,
    rustc_commit_date: String,
    rustc_host: String,
    rustc_llvm_version: String,
}

#[derive(Serialize)]
struct WorkloadEvidence {
    name: &'static str,
    warmup_iterations: usize,
    measured_iterations: usize,
    claimant_concurrency: usize,
}

#[derive(Serialize)]
struct ResultEvidence {
    duration_unit: &'static str,
    raw_sorted_samples_ns: Vec<u64>,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    winners: usize,
    denials: usize,
    provisional_p95_limit_ns: u64,
    meets_provisional_p95_limit: bool,
}

struct RustcEvidence {
    version_line: String,
    release: String,
    commit_hash: String,
    commit_date: String,
    host: String,
    llvm_version: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    if cfg!(debug_assertions) {
        return Err("eligibility_benchmark must be run with --release".into());
    }

    let options = parse_options()?;
    let hardware = required_hardware_label()?;
    let rustc = rustc_evidence()?;
    if rustc.release != PINNED_RUST_RELEASE {
        return Err(format!(
            "benchmark requires rustc {PINNED_RUST_RELEASE}, found {}",
            rustc.release
        )
        .into());
    }

    let corpus_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/plan-eligibility-v1/expected-outcomes.json");
    let corpus_bytes = std::fs::read(&corpus_path)?;
    validate_public_corpus(&corpus_bytes)?;
    let corpus_digest = Sha256Digest::digest(&corpus_bytes).to_string();
    if corpus_digest != PINNED_EXPECTED_OUTCOMES_SHA256 {
        return Err("expected-outcomes.json digest does not match the reviewed corpus".into());
    }

    let base_plan = authentic_plan();
    for _ in 0..options.warmups {
        let _sample_ns = evaluate_once(&base_plan)?;
    }

    let mut samples = Vec::with_capacity(options.iterations);
    let mut winners = 0_usize;
    for _ in 0..options.iterations {
        samples.push(evaluate_once(&base_plan)?);
        winners += 1;
    }
    let denials = options.iterations - winners;
    samples.sort_unstable();

    let p50_ns = percentile(&samples, 50);
    let p95_ns = percentile(&samples, 95);
    let p99_ns = percentile(&samples, 99);
    let max_ns = *samples.last().ok_or("benchmark produced no samples")?;
    let evidence = BenchmarkEvidence {
        schema: EVIDENCE_SCHEMA,
        acceptance_id: ACCEPTANCE_ID,
        corpus: CorpusEvidence {
            schema: CORPUS_SCHEMA,
            expected_outcomes_bytes: corpus_bytes.len(),
            expected_outcomes_sha256: corpus_digest.clone(),
            public_case_id: PUBLIC_CASE_ID,
        },
        environment: EnvironmentEvidence {
            hardware,
            available_parallelism: std::thread::available_parallelism()?.get(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            build_profile: "release",
            rustc_version_line: rustc.version_line,
            rustc_release: rustc.release,
            rustc_commit_hash: rustc.commit_hash,
            rustc_commit_date: rustc.commit_date,
            rustc_host: rustc.host,
            rustc_llvm_version: rustc.llvm_version,
        },
        workload: WorkloadEvidence {
            name: "coherent-evaluator-plus-fresh-deterministic-claimant",
            warmup_iterations: options.warmups,
            measured_iterations: options.iterations,
            claimant_concurrency: 1,
        },
        results: ResultEvidence {
            duration_unit: "nanoseconds",
            raw_sorted_samples_ns: samples,
            p50_ns,
            p95_ns,
            p99_ns,
            max_ns,
            winners,
            denials,
            provisional_p95_limit_ns: P95_LIMIT_NS,
            meets_provisional_p95_limit: p95_ns <= P95_LIMIT_NS,
        },
        limitations: [
            "local point-in-time performance evidence only",
            "deterministic in-memory claimant is not durable replay storage",
            "eligible marker is not preparation, grant, adapter, or effect authority",
        ],
    };

    write_new_evidence(&options.evidence, &evidence)?;
    println!(
        "PLAN-002 benchmark samples={} winners={} denials={} p50_ns={} p95_ns={} p99_ns={} max_ns={} corpus_sha256={}",
        options.iterations, winners, denials, p50_ns, p95_ns, p99_ns, max_ns, corpus_digest
    );
    Ok(())
}

fn parse_options() -> Result<Options, Box<dyn Error>> {
    let mut evidence = None;
    let mut warmups = DEFAULT_WARMUPS;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--evidence" => {
                let value = arguments.next().ok_or("--evidence requires a path")?;
                if evidence.replace(PathBuf::from(value)).is_some() {
                    return Err("--evidence may appear only once".into());
                }
            }
            "--warmups" => {
                warmups = parse_positive_count("--warmups", arguments.next())?;
            }
            "--iterations" => {
                iterations = parse_positive_count("--iterations", arguments.next())?;
            }
            _ => return Err(format!("unknown benchmark argument: {argument}").into()),
        }
    }

    Ok(Options {
        evidence: evidence.ok_or("--evidence is required")?,
        warmups,
        iterations,
    })
}

fn parse_positive_count(option: &str, value: Option<String>) -> Result<usize, Box<dyn Error>> {
    let value = value.ok_or_else(|| format!("{option} requires a positive integer"))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{option} must be greater than zero").into());
    }
    Ok(parsed)
}

fn required_hardware_label() -> Result<String, Box<dyn Error>> {
    let label = std::env::var("HELIX_BENCH_HARDWARE")?;
    if label.is_empty()
        || label.len() > 128
        || label.chars().any(char::is_control)
        || label.trim() != label
    {
        return Err("HELIX_BENCH_HARDWARE must be a trimmed, bounded public label".into());
    }
    Ok(label)
}

fn rustc_evidence() -> Result<RustcEvidence, Box<dyn Error>> {
    let output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()?;
    if !output.status.success() {
        return Err("rustc --version --verbose failed".into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    let mut lines = rendered.lines();
    let version_line = lines
        .next()
        .ok_or("rustc omitted its version line")?
        .to_owned();
    let field = |name: &str| -> Result<String, Box<dyn Error>> {
        rendered
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .map(str::to_owned)
            .ok_or_else(|| format!("rustc omitted {name}").into())
    };
    Ok(RustcEvidence {
        version_line,
        release: field("release:")?,
        commit_hash: field("commit-hash:")?,
        commit_date: field("commit-date:")?,
        host: field("host:")?,
        llvm_version: field("LLVM version:")?,
    })
}

fn validate_public_corpus(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let value: Value = serde_json::from_slice(bytes)?;
    if value.get("schema").and_then(Value::as_str) != Some(CORPUS_SCHEMA) {
        return Err("unexpected eligibility summary schema".into());
    }
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("eligibility summary omitted cases")?;
    let coherent = cases
        .iter()
        .find(|case| case.get("case_id").and_then(Value::as_str) == Some(PUBLIC_CASE_ID))
        .ok_or("eligibility summary omitted the public coherent case")?;
    if coherent.get("outcome").and_then(Value::as_str) != Some("eligible")
        || coherent.get("code").and_then(Value::as_str) != Some("NONE")
        || coherent.get("claimant_reached").and_then(Value::as_bool) != Some(true)
    {
        return Err("public coherent case is not an eligible claimed outcome".into());
    }
    Ok(())
}

fn evaluate_once(base_plan: &AuthenticPlanEnvelopeV1) -> Result<u64, Box<dyn Error>> {
    let plan = base_plan.clone();
    let ready = ReadyEligibilityContextV1::try_new(coherent_ready_input(&plan))?;
    let fixture = EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    };
    let claimant = DeterministicReplayClaimant::new();
    let started = Instant::now();
    let eligible = fixture
        .evaluate(&claimant)
        .map_err(|failure| format!("benchmark denied with {}", failure.denial().code()))?;
    let elapsed = u64::try_from(started.elapsed().as_nanos())?;
    if elapsed > MAX_SAFE_U64 {
        return Err("benchmark duration exceeds the portable integer range".into());
    }
    if claimant.call_count() != 1 || claimant.successful_claim_count() != 1 {
        return Err("deterministic claimant did not produce exactly one new claim".into());
    }
    let _observed = std::hint::black_box(eligible.bindings().replay_binding_digest());
    Ok(elapsed)
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn write_new_evidence(path: &Path, evidence: &BenchmarkEvidence) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(evidence)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
