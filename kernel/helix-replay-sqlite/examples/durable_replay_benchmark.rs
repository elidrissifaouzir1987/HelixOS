//! Controlled-host release evidence for fresh acknowledged durable replay claims.
//!
//! Fixture construction is outside each sample. The measured boundary is one complete
//! eligibility evaluation plus one fresh SQLite claim, including connection open/close,
//! `BEGIN IMMEDIATE`, WAL commit and `synchronous=FULL` acknowledgement.

#[path = "../tests/common/mod.rs"]
mod common;

use common::feature002;
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AuthenticPlanEnvelopeV1, ContractError,
    Ed25519KeyResolver, Nonce128, PlanInputV1, Result as ContractResult, RiskLevelV1,
};
use helix_plan_eligibility::{
    AuthorizationInputV1, AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1,
    EligibilityContextV1, EligibilityDenialV1, ReadyEligibilityContextV1,
};
use helix_replay_sqlite::{
    embedded_backup_manifest_schema_v1_sha256, embedded_schema_v1_sha256, ReplayStoreConfigV1,
    SqliteReplayClaimantV1, TrustedEmptyLocalRootV1, TrustedLocalStoreRootV1,
    REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const EVIDENCE_SCHEMA: &str = "helixos.durable-replay-store-benchmark/1";
const ACCEPTANCE_ID: &str = "PLAN-003";
const CASES_SCHEMA: &str = "helixos.durable-replay-store-cases/1";
const SUMMARY_SCHEMA: &str = "helixos.durable-replay-store-summary/1";
const CASES_SHA256: &str = "7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff";
const EXPECTED_SHA256: &str = "687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac";
const PINNED_RUST_RELEASE: &str = "1.96.1";
const RUSQLITE_VERSION: &str = "0.40.1";
const LIBSQLITE3_SYS_VERSION: &str = "0.38.1";
const DEFAULT_WARMUPS: usize = 500;
const DEFAULT_SAMPLES: usize = 10_000;
const MAX_TOTAL_CLAIMS: usize = 100_000;
const P95_LIMIT_NS: u64 = 25_000_000;
const P99_LIMIT_NS: u64 = 100_000_000;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    output: PathBuf,
    warmups: usize,
    samples: usize,
}

#[derive(Serialize)]
struct BenchmarkEvidence {
    schema: &'static str,
    acceptance_id: &'static str,
    immutable_commit: String,
    worktree_clean_at_start: bool,
    corpus: CorpusEvidence,
    environment: EnvironmentEvidence,
    storage: StorageEvidence,
    workload: WorkloadEvidence,
    results: ResultEvidence,
    limitations: [&'static str; 5],
}

#[derive(Serialize)]
struct CorpusEvidence {
    cases_schema: &'static str,
    cases_count: usize,
    cases_bytes: usize,
    cases_sha256: String,
    expected_outcomes_schema: &'static str,
    expected_outcomes_bytes: usize,
    expected_outcomes_sha256: String,
}

#[derive(Serialize)]
struct EnvironmentEvidence {
    hardware: String,
    filesystem_assurance: String,
    available_parallelism: usize,
    os: &'static str,
    architecture: &'static str,
    build_profile: &'static str,
    rustc_version_line: String,
    rustc_release: String,
    rustc_commit_hash: String,
    rustc_commit_date: String,
    rustc_host: String,
    rustc_llvm_version: String,
}

#[derive(Serialize)]
struct StorageEvidence {
    crate_version: &'static str,
    rusqlite_version: &'static str,
    libsqlite3_sys_version: &'static str,
    sqlite_version: String,
    sqlite_source_id: String,
    application_id: i64,
    store_schema_version: i64,
    store_schema_sha256: String,
    backup_manifest_schema_sha256: String,
    journal_mode: &'static str,
    synchronous: &'static str,
    wal_autocheckpoint_pages: u64,
    connection_lifecycle: &'static str,
    profile_verification: &'static str,
}

#[derive(Serialize)]
struct WorkloadEvidence {
    name: &'static str,
    fixture_boundary: &'static str,
    measured_boundary: &'static str,
    warmup_claims: usize,
    measured_claims: usize,
    claimant_concurrency: usize,
    replay_clock: &'static str,
    root_created_new: bool,
    native_root_recorded: bool,
}

#[derive(Serialize)]
struct ResultEvidence {
    duration_unit: &'static str,
    raw_sorted_samples_ns: Vec<u64>,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    acknowledged_winners: usize,
    denials: usize,
    final_claim_count: u64,
    final_claimant_generation: u64,
    reopen_verified: bool,
    post_reopen_exact_denials: usize,
    post_reopen_conflict_denials: usize,
    p95_limit_ns: u64,
    p99_limit_ns: u64,
    meets_p95_limit: bool,
    meets_p99_limit: bool,
}

#[derive(Clone, Copy)]
enum BenchmarkVariant {
    Exact,
    SameNonceDifferentOperation,
    SameOperationDifferentNonce,
}

struct RustcEvidence {
    version_line: String,
    release: String,
    commit_hash: String,
    commit_date: String,
    host: String,
    llvm_version: String,
}

struct FixtureResolver {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for FixtureResolver {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == feature002::KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    if cfg!(debug_assertions) {
        return Err("durable_replay_benchmark must be run with --release".into());
    }

    let options = parse_options()?;
    let hardware = required_public_label("HELIX_BENCH_HARDWARE")?;
    let filesystem_assurance = required_public_label("HELIX_BENCH_FILESYSTEM_ASSURANCE")?;
    let rustc = rustc_evidence()?;
    if rustc.release != PINNED_RUST_RELEASE {
        return Err(format!(
            "benchmark requires rustc {PINNED_RUST_RELEASE}, found {}",
            rustc.release
        )
        .into());
    }
    let immutable_commit = clean_git_commit()?;
    let corpus = corpus_evidence()?;
    let (root, output) = preflight_paths(&options.root, &options.output)?;
    let claimant = create_new_claimant(&root)?;

    for index in 0..options.warmups {
        let fixture = benchmark_fixture(index)?;
        let _elapsed_ns = evaluate_fresh_once(fixture, &claimant, index + 1)?;
    }

    let mut raw_samples = Vec::with_capacity(options.samples);
    for offset in 0..options.samples {
        let index = options.warmups + offset;
        let fixture = benchmark_fixture(index)?;
        raw_samples.push(evaluate_fresh_once(fixture, &claimant, index + 1)?);
    }
    raw_samples.sort_unstable();

    let p50_ns = percentile(&raw_samples, 50);
    let p95_ns = percentile(&raw_samples, 95);
    let p99_ns = percentile(&raw_samples, 99);
    let max_ns = *raw_samples.last().ok_or("benchmark produced no samples")?;
    let expected_total = options
        .warmups
        .checked_add(options.samples)
        .ok_or("benchmark claim count overflow")?;
    let expected_total_u64 = u64::try_from(expected_total)?;
    let verification = claimant
        .verify_integrity_v1(common::MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .map_err(|error| format!("final store verification failed with {}", error.code()))?;
    if verification.claim_count() != expected_total_u64
        || verification.claimant_generation() != expected_total_u64
    {
        return Err("final store verification count mismatch".into());
    }
    drop(claimant);

    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root.clone())
        .map_err(|error| format!("benchmark reopen root rejected with {}", error.code()))?;
    let reopen_config = ReplayStoreConfigV1::try_new(
        trusted,
        common::DEFAULT_BUSY_WAIT_MS,
        common::DEFAULT_BACKUP_STEP_PAGES,
        common::DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .map_err(|error| format!("benchmark reopen config rejected with {}", error.code()))?;
    let reopened = SqliteReplayClaimantV1::open_or_create(
        reopen_config,
        common::InjectedClock::coherent(),
        common::OPEN_DEADLINE_MONOTONIC_MS,
    )
    .map_err(|error| format!("benchmark reopen failed with {}", error.code()))?;
    expect_replay_denial(
        benchmark_fixture_variant(0, BenchmarkVariant::Exact)?,
        &reopened,
        EligibilityDenialV1::ReplayAlreadyClaimed,
    )?;
    expect_replay_denial(
        benchmark_fixture_variant(0, BenchmarkVariant::SameNonceDifferentOperation)?,
        &reopened,
        EligibilityDenialV1::ReplayBindingConflict,
    )?;
    expect_replay_denial(
        benchmark_fixture_variant(0, BenchmarkVariant::SameOperationDifferentNonce)?,
        &reopened,
        EligibilityDenialV1::ReplayBindingConflict,
    )?;
    let verification = reopened
        .verify_integrity_v1(common::MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .map_err(|error| format!("reopened store verification failed with {}", error.code()))?;
    if verification.claim_count() != expected_total_u64
        || verification.claimant_generation() != expected_total_u64
    {
        return Err("reopen repeat/conflict probes changed the durable claim count".into());
    }

    let meets_p95_limit = p95_ns <= P95_LIMIT_NS;
    let meets_p99_limit = p99_ns <= P99_LIMIT_NS;
    let evidence = BenchmarkEvidence {
        schema: EVIDENCE_SCHEMA,
        acceptance_id: ACCEPTANCE_ID,
        immutable_commit,
        worktree_clean_at_start: true,
        corpus,
        environment: EnvironmentEvidence {
            hardware,
            filesystem_assurance,
            available_parallelism: std::thread::available_parallelism()?.get(),
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            build_profile: "release",
            rustc_version_line: rustc.version_line,
            rustc_release: rustc.release,
            rustc_commit_hash: rustc.commit_hash,
            rustc_commit_date: rustc.commit_date,
            rustc_host: rustc.host,
            rustc_llvm_version: rustc.llvm_version,
        },
        storage: StorageEvidence {
            crate_version: env!("CARGO_PKG_VERSION"),
            rusqlite_version: RUSQLITE_VERSION,
            libsqlite3_sys_version: LIBSQLITE3_SYS_VERSION,
            sqlite_version: rusqlite::version().to_owned(),
            sqlite_source_id: rusqlite::ffi::SQLITE_SOURCE_ID.to_str()?.to_owned(),
            application_id: REPLAY_STORE_APPLICATION_ID_V1,
            store_schema_version: REPLAY_STORE_SCHEMA_VERSION_V1,
            store_schema_sha256: bytes_hex(&embedded_schema_v1_sha256()),
            backup_manifest_schema_sha256: bytes_hex(&embedded_backup_manifest_schema_v1_sha256()),
            journal_mode: "WAL",
            synchronous: "FULL",
            wal_autocheckpoint_pages: 0,
            connection_lifecycle: "fresh-open-through-close-per-claim",
            profile_verification: "store-open-and-each-claim-fail-closed",
        },
        workload: WorkloadEvidence {
            name: "complete-eligibility-plus-fresh-durable-sqlite-claim",
            fixture_boundary: "signed-plan-and-ready-context-built-before-each-sample",
            measured_boundary: "evaluator-through-acknowledged-claim-and-connection-close",
            warmup_claims: options.warmups,
            measured_claims: options.samples,
            claimant_concurrency: 1,
            replay_clock: "fixed-injected-boot-monotonic-sample",
            root_created_new: true,
            native_root_recorded: false,
        },
        results: ResultEvidence {
            duration_unit: "nanoseconds",
            raw_sorted_samples_ns: raw_samples,
            p50_ns,
            p95_ns,
            p99_ns,
            max_ns,
            acknowledged_winners: options.samples,
            denials: 0,
            final_claim_count: verification.claim_count(),
            final_claimant_generation: verification.claimant_generation(),
            reopen_verified: true,
            post_reopen_exact_denials: 1,
            post_reopen_conflict_denials: 2,
            p95_limit_ns: P95_LIMIT_NS,
            p99_limit_ns: P99_LIMIT_NS,
            meets_p95_limit,
            meets_p99_limit,
        },
        limitations: [
            "controlled-host point-in-time evidence only",
            "filesystem assurance is a bounded caller-provided public label, not auto-detection",
            "acknowledged process commits are not power-loss or F_FULLFSYNC evidence",
            "fixed injected replay clock isolates storage latency from deadline-clock drift",
            "eligibility evidence is not preparation, dispatch, adapter, or effect authority",
        ],
    };

    write_new_evidence(&output, &evidence)?;
    println!(
        "PLAN-003 samples={} winners={} denials=0 p50_ns={} p95_ns={} p99_ns={} max_ns={} cases_sha256={} expected_sha256={}",
        options.samples, options.samples, p50_ns, p95_ns, p99_ns, max_ns, CASES_SHA256,
        EXPECTED_SHA256
    );
    if !meets_p95_limit || !meets_p99_limit {
        return Err("controlled-host latency budget exceeded; evidence was retained".into());
    }
    Ok(())
}

fn parse_options() -> Result<Options, Box<dyn Error>> {
    let mut root = None;
    let mut output = None;
    let mut warmups = DEFAULT_WARMUPS;
    let mut samples = DEFAULT_SAMPLES;
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => set_path_option("--root", &mut root, arguments.next())?,
            "--output" => set_path_option("--output", &mut output, arguments.next())?,
            "--warmups" => warmups = parse_count("--warmups", arguments.next())?,
            "--samples" => samples = parse_count("--samples", arguments.next())?,
            _ => return Err("unknown benchmark argument".into()),
        }
    }
    if warmups < DEFAULT_WARMUPS {
        return Err("--warmups must be at least 500 for PLAN-003 evidence".into());
    }
    if samples < DEFAULT_SAMPLES {
        return Err("--samples must be at least 10000 for PLAN-003 evidence".into());
    }
    if warmups
        .checked_add(samples)
        .is_none_or(|total| total > MAX_TOTAL_CLAIMS)
    {
        return Err("benchmark total claim count exceeds the bounded evidence limit".into());
    }
    Ok(Options {
        root: root.ok_or("--root is required")?,
        output: output.ok_or("--output is required")?,
        warmups,
        samples,
    })
}

fn set_path_option(
    option: &str,
    destination: &mut Option<PathBuf>,
    value: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let value = value.ok_or_else(|| format!("{option} requires a path"))?;
    if destination.replace(PathBuf::from(value)).is_some() {
        return Err(format!("{option} may appear only once").into());
    }
    Ok(())
}

fn parse_count(option: &str, value: Option<String>) -> Result<usize, Box<dyn Error>> {
    let value = value.ok_or_else(|| format!("{option} requires a positive integer"))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{option} must be greater than zero").into());
    }
    Ok(parsed)
}

fn required_public_label(variable: &str) -> Result<String, Box<dyn Error>> {
    let label = std::env::var(variable).map_err(|_| format!("{variable} is required"))?;
    if label.is_empty()
        || label.len() > 160
        || label.trim() != label
        || label.chars().any(char::is_control)
        || label.contains(['/', '\\'])
    {
        return Err(format!("{variable} must be a trimmed, bounded, non-path public label").into());
    }
    Ok(label)
}

fn preflight_paths(root: &Path, output: &Path) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let root = normalize_absolute(root)?;
    let output = normalize_absolute(output)?;
    if output.starts_with(&root) {
        return Err("--output must be outside the dedicated replay root".into());
    }
    match std::fs::symlink_metadata(&root) {
        Ok(_) => return Err("--root must identify a new path".into()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err("--root availability check failed".into()),
    }
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|_| "output parent creation failed")?;
    }
    match std::fs::symlink_metadata(&output) {
        Ok(_) => return Err("--output must identify a new file".into()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err("--output availability check failed".into()),
    }
    Ok((root, output))
}

fn normalize_absolute(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "current directory unavailable")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("path normalization escaped its filesystem root".into());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    if !normalized.is_absolute() {
        return Err("path normalization did not produce an absolute path".into());
    }
    Ok(normalized)
}

fn create_new_claimant(
    root: &Path,
) -> Result<SqliteReplayClaimantV1<common::InjectedClock>, Box<dyn Error>> {
    std::fs::create_dir(root).map_err(|_| "dedicated replay root creation failed")?;
    let trusted = TrustedEmptyLocalRootV1::try_from_provisioned(root.to_path_buf())
        .map_err(|error| format!("dedicated replay root rejected with {}", error.code()))?;
    let config = ReplayStoreConfigV1::try_new(
        trusted.into_store_root(),
        common::DEFAULT_BUSY_WAIT_MS,
        common::DEFAULT_BACKUP_STEP_PAGES,
        common::DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .map_err(|error| format!("replay configuration rejected with {}", error.code()))?;
    SqliteReplayClaimantV1::open_or_create(
        config,
        common::InjectedClock::coherent(),
        common::OPEN_DEADLINE_MONOTONIC_MS,
    )
    .map_err(|error| format!("replay store open failed with {}", error.code()).into())
}

fn benchmark_fixture(index: usize) -> Result<feature002::EligibilityFixture, Box<dyn Error>> {
    benchmark_fixture_variant(index, BenchmarkVariant::Exact)
}

fn benchmark_fixture_variant(
    index: usize,
    variant: BenchmarkVariant,
) -> Result<feature002::EligibilityFixture, Box<dyn Error>> {
    let sequence = u64::try_from(index)?;
    let operation = match variant {
        BenchmarkVariant::Exact | BenchmarkVariant::SameOperationDifferentNonce => {
            format!("operation:benchmark-{sequence:016x}")
        }
        BenchmarkVariant::SameNonceDifferentOperation => {
            format!("operation:benchmark-conflict-{sequence:016x}")
        }
    };
    let operation_id: &'static str = Box::leak(operation.into_boxed_str());
    let mut nonce_bytes = [0x42_u8; 16];
    nonce_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    if matches!(variant, BenchmarkVariant::SameOperationDifferentNonce) {
        nonce_bytes[0] ^= 0x80;
    }
    let nonce = Nonce128::from_bytes(nonce_bytes);

    let mut input: PlanInputV1 = feature002::sample_plan_input();
    input.operation_id = operation_id.to_owned();
    input.nonce = nonce;
    let plan = authenticate_plan(input)?;
    let plan_id = plan.eligibility_claims().plan_id();
    let mut ready_input = feature002::coherent_ready_input(&plan);
    ready_input.authorization = AuthorizationViewV1::Current(
        AuthorizationRecordV1::try_new(AuthorizationInputV1 {
            status: AuthorizationStatusV1::Granted,
            plan_id,
            operation_id,
            risk_level: RiskLevelV1::L1,
            nonce,
            evidence_digest: feature002::digest(b"benchmark authorization evidence"),
            authorization_generation: feature002::AUTHORIZATION_GENERATION,
            boot_id: feature002::BOOT_ID,
            not_before_utc_unix_ms: feature002::ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: feature002::ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        })
        .map_err(|_| "benchmark authorization construction failed")?,
    );
    let ready = ReadyEligibilityContextV1::try_new(ready_input)
        .map_err(|_| "benchmark eligibility context construction failed")?;
    Ok(feature002::EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    })
}

fn expect_replay_denial(
    fixture: feature002::EligibilityFixture,
    claimant: &SqliteReplayClaimantV1<common::InjectedClock>,
    expected: EligibilityDenialV1,
) -> Result<(), Box<dyn Error>> {
    let failure = fixture
        .evaluate(claimant)
        .err()
        .ok_or("post-reopen replay probe was unexpectedly eligible")?;
    if failure.denial() != expected {
        return Err(format!(
            "post-reopen replay probe returned {}, expected {}",
            failure.denial().code(),
            expected.code()
        )
        .into());
    }
    Ok(())
}

fn authenticate_plan(input: PlanInputV1) -> Result<AuthenticPlanEnvelopeV1, Box<dyn Error>> {
    let signer = feature002::TestSigner::fixed();
    let resolver = FixtureResolver {
        public_key: signer.verifying_key_bytes(),
    };
    let signed = sign_plan_v1(input, &signer).map_err(|_| "benchmark plan signing failed")?;
    let wire = signed
        .to_canonical_json()
        .map_err(|_| "benchmark plan canonicalization failed")?;
    decode_and_verify_plan(&wire, &resolver)
        .map_err(|_| "benchmark plan authentication failed".into())
}

fn evaluate_fresh_once(
    fixture: feature002::EligibilityFixture,
    claimant: &SqliteReplayClaimantV1<common::InjectedClock>,
    expected_generation: usize,
) -> Result<u64, Box<dyn Error>> {
    let started = Instant::now();
    let result = fixture.evaluate(claimant);
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos())?;
    let eligible = result
        .map_err(|failure| format!("benchmark claim denied with {}", failure.denial().code()))?;
    if eligible.replay_claim().claimant_generation() != u64::try_from(expected_generation)? {
        return Err("benchmark claimant generation was not sequential".into());
    }
    let _observed = std::hint::black_box(eligible.bindings().replay_binding_digest());
    Ok(elapsed_ns)
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn corpus_evidence() -> Result<CorpusEvidence, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/durable-replay-store-v1");
    let cases = std::fs::read(base.join("cases.json"))?;
    let expected = std::fs::read(base.join("expected-outcomes.json"))?;
    let cases_digest = sha256_hex(&cases);
    let expected_digest = sha256_hex(&expected);
    if cases_digest != CASES_SHA256 || expected_digest != EXPECTED_SHA256 {
        return Err("durable replay corpus digest does not match the reviewed fixture".into());
    }
    let cases_value: Value = serde_json::from_slice(&cases)?;
    let expected_value: Value = serde_json::from_slice(&expected)?;
    if cases_value.get("schema").and_then(Value::as_str) != Some(CASES_SCHEMA)
        || expected_value.get("schema").and_then(Value::as_str) != Some(SUMMARY_SCHEMA)
    {
        return Err("durable replay corpus schema does not match the reviewed fixture".into());
    }
    let cases_count = cases_value
        .get("cases")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or("durable replay corpus omitted cases")?;
    if cases_count != 68 {
        return Err("durable replay corpus case count does not match the reviewed fixture".into());
    }
    Ok(CorpusEvidence {
        cases_schema: CASES_SCHEMA,
        cases_count,
        cases_bytes: cases.len(),
        cases_sha256: cases_digest,
        expected_outcomes_schema: SUMMARY_SCHEMA,
        expected_outcomes_bytes: expected.len(),
        expected_outcomes_sha256: expected_digest,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_hex(&Sha256::digest(bytes))
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn rustc_evidence() -> Result<RustcEvidence, Box<dyn Error>> {
    let output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()?;
    if !output.status.success() {
        return Err("rustc --version --verbose failed".into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    let version_line = rendered
        .lines()
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

fn clean_git_commit() -> Result<String, Box<dyn Error>> {
    let repository = env!("CARGO_MANIFEST_DIR");
    let commit = command_stdout("git", &["-C", repository, "rev-parse", "HEAD"])?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("git did not return a full lowercase commit ID".into());
    }
    let status = command_stdout(
        "git",
        &[
            "-C",
            repository,
            "status",
            "--porcelain",
            "--untracked-files=normal",
        ],
    )?;
    if !status.is_empty() {
        return Err("benchmark requires a clean immutable worktree".into());
    }
    Ok(commit)
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err("benchmark metadata command failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn write_new_evidence(path: &Path, evidence: &BenchmarkEvidence) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(evidence)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
