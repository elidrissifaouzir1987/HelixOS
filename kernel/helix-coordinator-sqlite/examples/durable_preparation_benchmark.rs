//! Controlled-host PLAN-004 coordinator and recovery-transfer benchmark evidence.
//!
//! Every coordinator sample consumes one already-authenticated, already-eligible
//! unique signed plan through the real `prepare_plan_v1` orchestrator and production
//! `SqliteCoordinatorStoreV1` commit adapter. The measured interval is therefore a
//! conservative upper bound around final comparison plus the canonical durable commit.
//! Recovery transfer is measured separately and never enters coordinator percentiles.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError,
    Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128, PlanInputV1,
    RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1, Result as ContractResult,
    RiskLevelV1, Sha256Digest,
};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorClockUnavailableV1, CoordinatorMonotonicClockV1,
    CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1, SqliteCoordinatorStoreV1,
    COORDINATOR_STORE_APPLICATION_ID_V1, COORDINATOR_STORE_SCHEMA_VERSION_V1,
};
use helix_plan_preparation::{
    build_controlled_benchmark_case_v1, ControlledBenchmarkCaseV1, ControlledBenchmarkClockV1,
    CONTROLLED_BENCHMARK_BOOT_ID_V1, CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
    CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1, CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
    CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1, CONTROLLED_BENCHMARK_KEY_ID_V1,
    CONTROLLED_BENCHMARK_POLICY_VERSION_V1, CONTROLLED_BENCHMARK_WORKLOAD_ID_V1,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const EVIDENCE_SCHEMA_V1: &str = "helixos.durable-preparation-benchmark/1";
const RECOVERY_EVIDENCE_SCHEMA_V1: &str = "helixos.durable-preparation-recovery-transfer/1";
const ACCEPTANCE_ID: &str = "PLAN-004";
const PINNED_RUST_RELEASE: &str = "1.96.1";
const RUSQLITE_VERSION: &str = "0.40.1";
const LIBSQLITE3_SYS_VERSION: &str = "0.38.1";
const BUNDLED_SQLITE_VERSION: &str = "3.53.2";
const BUNDLED_SQLITE_SOURCE_ID: &str =
    "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24";
const CASES_SHA256: &str = "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d";
const EXPECTED_SHA256: &str = "87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b";
const STORE_SCHEMA_SHA256: &str =
    "e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e";
const BACKUP_SCHEMA_SHA256: &str =
    "163cfd72f54983f993b2d5f6ad3fcd00df84a1b8cbc7eb971fcc8c1d0019199e";
const PROVENANCE_SCHEMA_SHA256: &str =
    "6b752fc1a8f0c92fd69a03ce418d07087e615eaf55f3b2e1959668e15237728f";
const RECOVERY_ROOT_SCHEMA_SHA256: &str =
    "0fb080c12df1b1e99ef7d0a19ca53ded97d8d170e0c2825e93fd3d57c53bf25f";
const RECOVERY_SNAPSHOT_SCHEMA_SHA256: &str =
    "371e94fbf5c52d462e8363c9b3237a57288c4b0ae1c766e12c2c904d5f6cf646";
const DEFAULT_WARMUPS: usize = 500;
const DEFAULT_SAMPLES: usize = 10_000;
const MAX_TOTAL_OPERATIONS: usize = 100_000;
const P95_LIMIT_NS: u64 = 25_000_000;
const P99_LIMIT_NS: u64 = 100_000_000;
const BUSY_WAIT_MS: u64 = 50;
const SAMPLE_DEADLINE_BUDGET_MS: u64 = 60_000;
const INITIALIZATION_DEADLINE_BUDGET_MS: u64 = 60_000;
const REOPEN_DEADLINE_BUDGET_MS: u64 = 600_000;
const ELIGIBILITY_RUN_WINDOW_MS: u64 = 12 * 60 * 60 * 1_000;
const RECOVERY_TRANSFER_BYTES: u64 = 16 * 1024 * 1024;
const RECOVERY_CHUNK_BYTES: usize = 1024 * 1024;
const SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const EXPECTED_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/expected-outcomes.json");
const BACKUP_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/preparation-backup-manifest-v1.schema.json"
);
const PROVENANCE_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/preparation-backup-provenance-attestation-v1.schema.json"
);
const RECOVERY_ROOT_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/recovery-root-metadata-v1.schema.json"
);
const RECOVERY_SNAPSHOT_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/recovery-snapshot-manifest-v1.schema.json"
);

#[derive(Debug, PartialEq, Eq)]
struct Options {
    coordinator_root: PathBuf,
    recovery_root: PathBuf,
    output: PathBuf,
    warmups: usize,
    samples: usize,
}

#[derive(Serialize)]
struct CoordinatorEvidenceV1 {
    schema: &'static str,
    acceptance_id: &'static str,
    immutable_commit: String,
    worktree_clean_at_start: bool,
    corpus: CorpusEvidenceV1,
    environment: EnvironmentEvidenceV1,
    storage: StorageEvidenceV1,
    workload: CoordinatorWorkloadEvidenceV1,
    results: CoordinatorResultEvidenceV1,
    recovery_transfer: RecoveryArtifactReferenceV1,
    limitations: [&'static str; 5],
}

#[derive(Serialize)]
struct RecoveryTransferEvidenceV1 {
    schema: &'static str,
    acceptance_id: &'static str,
    immutable_commit: String,
    hardware: String,
    filesystem_assurance: String,
    at_rest_profile: String,
    material_bytes: u64,
    chunk_bytes: usize,
    write_sync_close_ns: u64,
    reopen_verify_ns: u64,
    total_ns: u64,
    throughput_bytes_per_second: u64,
    material_sha256: String,
    reopened_sha256: String,
    root_created_new: bool,
    native_root_recorded: bool,
    included_in_coordinator_percentiles: bool,
    evidence_class: &'static str,
}

#[derive(Serialize)]
struct CorpusEvidenceV1 {
    case_count: usize,
    fault_boundary_count: usize,
    cases_sha256: &'static str,
    expected_outcomes_sha256: &'static str,
    coordinator_schema_sha256: &'static str,
    backup_manifest_schema_sha256: &'static str,
    provenance_attestation_schema_sha256: &'static str,
    recovery_root_schema_sha256: &'static str,
    recovery_snapshot_schema_sha256: &'static str,
}

#[derive(Serialize)]
struct EnvironmentEvidenceV1 {
    hardware: String,
    detected_hardware: String,
    filesystem_assurance: String,
    at_rest_profile: String,
    os: &'static str,
    os_build: String,
    architecture: &'static str,
    available_parallelism: usize,
    build_profile: &'static str,
    rustc_version_line: String,
    rustc_release: String,
    rustc_commit_hash: String,
    rustc_commit_date: String,
    rustc_host: String,
    rustc_llvm_version: String,
}

#[derive(Serialize)]
struct StorageEvidenceV1 {
    crate_version: &'static str,
    rusqlite_version: &'static str,
    libsqlite3_sys_version: &'static str,
    sqlite_version: String,
    sqlite_source_id: String,
    application_id: i64,
    schema_version: i64,
    journal_mode: &'static str,
    synchronous: &'static str,
    wal_autocheckpoint_pages: u64,
    foreign_keys: &'static str,
    trusted_schema: &'static str,
    cell_size_check: &'static str,
    recursive_triggers: &'static str,
}

#[derive(Serialize)]
struct CoordinatorWorkloadEvidenceV1 {
    name: &'static str,
    measured_boundary: &'static str,
    fixture_boundary: &'static str,
    warmup_operations: usize,
    measured_operations: usize,
    concurrency: usize,
    canonical_commit_members: usize,
    connection_lifecycle: &'static str,
    root_created_new: bool,
    native_root_recorded: bool,
    synthetic_values_public: bool,
    signed_unique_plans: bool,
    eligibility_precomputed_outside_samples: bool,
    budget_scopes_preprovisioned_outside_samples: bool,
    irreversible_recovery_provider_calls: usize,
    caller_deadlines: &'static str,
}

#[derive(Serialize)]
struct CoordinatorResultEvidenceV1 {
    duration_unit: &'static str,
    raw_sorted_samples_ns: Vec<u64>,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    committed_operations: u64,
    final_store_generation: u64,
    final_operation_generation: u64,
    final_budget_generation: u64,
    final_event_generation: u64,
    quick_check_ok: bool,
    foreign_keys_ok: bool,
    close_reopen_verified: bool,
    p95_limit_ns: u64,
    p99_limit_ns: u64,
    meets_p95_limit: bool,
    meets_p99_limit: bool,
}

#[derive(Serialize)]
struct RecoveryArtifactReferenceV1 {
    separate_artifact: bool,
    artifact_sha256: String,
    artifact_bytes: u64,
    included_in_coordinator_percentiles: bool,
}

struct RustcEvidenceV1 {
    version_line: String,
    release: String,
    commit_hash: String,
    commit_date: String,
    host: String,
    llvm_version: String,
}

struct SampleFixtureV1 {
    case: ControlledBenchmarkCaseV1,
}

#[derive(Clone, Debug)]
struct BenchmarkCoordinatorClockV1(ControlledBenchmarkClockV1);

impl CoordinatorMonotonicClockV1 for BenchmarkCoordinatorClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        self.0
            .now_absolute_monotonic_ms_v1()
            .map_err(|_| CoordinatorClockUnavailableV1)
    }
}

#[derive(Debug)]
struct BenchmarkPlanSignerV1 {
    key: SigningKey,
}

impl BenchmarkPlanSignerV1 {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&SIGNING_KEY_BYTES_V1),
        }
    }

    fn resolver_v1(&self) -> BenchmarkPlanResolverV1 {
        BenchmarkPlanResolverV1 {
            public_key: self.key.verifying_key().to_bytes(),
        }
    }
}

impl Ed25519Signer for BenchmarkPlanSignerV1 {
    fn key_id(&self) -> &str {
        CONTROLLED_BENCHMARK_KEY_ID_V1
    }

    fn sign_ed25519(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

#[derive(Clone, Debug)]
struct BenchmarkPlanResolverV1 {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for BenchmarkPlanResolverV1 {
    fn resolve_ed25519(&self, key_id: &str) -> Result<[u8; 32], ContractError> {
        if key_id == CONTROLLED_BENCHMARK_KEY_ID_V1 {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

type BenchmarkStoreV1 =
    SqliteCoordinatorStoreV1<BenchmarkCoordinatorClockV1, BenchmarkPlanResolverV1>;

fn main() -> Result<(), Box<dyn Error>> {
    if cfg!(debug_assertions) {
        return Err("durable_preparation_benchmark must be run with --release".into());
    }

    let options = parse_options_from(std::env::args().skip(1))?;
    let detected_hardware = require_physical_m4_v1()?;
    let hardware = required_public_label("HELIX_BENCH_HARDWARE")?;
    let filesystem_assurance = required_public_label("HELIX_BENCH_FILESYSTEM_ASSURANCE")?;
    let at_rest_profile = required_public_label("HELIX_BENCH_AT_REST_PROFILE")?;
    let rustc = rustc_evidence_v1()?;
    if rustc.release != PINNED_RUST_RELEASE {
        return Err(format!(
            "benchmark requires rustc {PINNED_RUST_RELEASE}, found {}",
            rustc.release
        )
        .into());
    }
    require_sqlite_pin_v1()?;
    let immutable_commit = clean_git_commit_v1()?;
    let corpus = corpus_evidence_v1()?;
    let paths = preflight_paths_v1(&options)?;

    let clock = ControlledBenchmarkClockV1::start_v1();
    let coordinator_clock = BenchmarkCoordinatorClockV1(clock.clone());
    let signer = BenchmarkPlanSignerV1::new();
    let resolver = signer.resolver_v1();
    let (store, root_identity) = initialize_coordinator_root_v1(
        &paths.coordinator_root,
        coordinator_clock.clone(),
        resolver.clone(),
        clock.deadline_after_ms_v1(INITIALIZATION_DEADLINE_BUDGET_MS)?,
    )?;
    fs::create_dir(&paths.recovery_root).map_err(|_| "dedicated recovery root creation failed")?;
    let database = paths.coordinator_root.join("coordinator.sqlite3");
    let total_operations = options
        .warmups
        .checked_add(options.samples)
        .ok_or("benchmark operation count overflow")?;
    let eligibility_deadline = clock.deadline_after_ms_v1(ELIGIBILITY_RUN_WINDOW_MS)?;
    let fixtures = (1..=total_operations)
        .map(|index| SampleFixtureV1::try_new(index, &signer, clock.clone(), eligibility_deadline))
        .collect::<Result<Vec<_>, _>>()?;
    provision_scopes_v1(&database, &fixtures)?;

    let mut fixtures = fixtures.into_iter();
    let mut irreversible_recovery_provider_calls = 0_usize;
    for fixture in fixtures.by_ref().take(options.warmups) {
        let (_, provider_calls) = commit_once_v1(&store, fixture, &clock)?;
        irreversible_recovery_provider_calls = irreversible_recovery_provider_calls
            .checked_add(provider_calls)
            .ok_or("recovery-provider call count overflow")?;
    }
    let mut samples = Vec::with_capacity(options.samples);
    for fixture in fixtures {
        let (duration, provider_calls) = commit_once_v1(&store, fixture, &clock)?;
        irreversible_recovery_provider_calls = irreversible_recovery_provider_calls
            .checked_add(provider_calls)
            .ok_or("recovery-provider call count overflow")?;
        samples.push(duration);
    }
    if irreversible_recovery_provider_calls != 0 {
        return Err("irreversible coordinator workload called recovery provider".into());
    }
    samples.sort_unstable();
    let p50_ns = percentile_v1(&samples, 50);
    let p95_ns = percentile_v1(&samples, 95);
    let p99_ns = percentile_v1(&samples, 99);
    let max_ns = *samples.last().ok_or("benchmark produced no samples")?;
    drop(store);
    let verification = verify_reopened_coordinator_v1(
        &paths.coordinator_root,
        &database,
        root_identity,
        coordinator_clock,
        resolver,
        clock.deadline_after_ms_v1(REOPEN_DEADLINE_BUDGET_MS)?,
        u64::try_from(total_operations)?,
    )?;

    let recovery = run_recovery_transfer_v1(
        &paths.recovery_root,
        immutable_commit.clone(),
        hardware.clone(),
        filesystem_assurance.clone(),
        at_rest_profile.clone(),
    )?;
    require_same_clean_git_commit_v1(&immutable_commit)?;
    let recovery_artifact = write_new_evidence_v1(&paths.recovery_output, &recovery)?;

    let meets_p95_limit = p95_ns <= P95_LIMIT_NS;
    let meets_p99_limit = p99_ns <= P99_LIMIT_NS;
    let evidence = CoordinatorEvidenceV1 {
        schema: EVIDENCE_SCHEMA_V1,
        acceptance_id: ACCEPTANCE_ID,
        immutable_commit,
        worktree_clean_at_start: true,
        corpus,
        environment: EnvironmentEvidenceV1 {
            hardware,
            detected_hardware,
            filesystem_assurance,
            at_rest_profile,
            os: std::env::consts::OS,
            os_build: os_build_evidence_v1()?,
            architecture: std::env::consts::ARCH,
            available_parallelism: std::thread::available_parallelism()?.get(),
            build_profile: "release",
            rustc_version_line: rustc.version_line,
            rustc_release: rustc.release,
            rustc_commit_hash: rustc.commit_hash,
            rustc_commit_date: rustc.commit_date,
            rustc_host: rustc.host,
            rustc_llvm_version: rustc.llvm_version,
        },
        storage: StorageEvidenceV1 {
            crate_version: env!("CARGO_PKG_VERSION"),
            rusqlite_version: RUSQLITE_VERSION,
            libsqlite3_sys_version: LIBSQLITE3_SYS_VERSION,
            sqlite_version: rusqlite::version().to_owned(),
            sqlite_source_id: rusqlite::ffi::SQLITE_SOURCE_ID.to_str()?.to_owned(),
            application_id: COORDINATOR_STORE_APPLICATION_ID_V1,
            schema_version: COORDINATOR_STORE_SCHEMA_VERSION_V1,
            journal_mode: "WAL",
            synchronous: "FULL",
            wal_autocheckpoint_pages: 0,
            foreign_keys: "ON",
            trusted_schema: "OFF",
            cell_size_check: "ON",
            recursive_triggers: "ON",
        },
        workload: CoordinatorWorkloadEvidenceV1 {
            name: "production-prepare-plan-v1-irreversible-conservative-upper-bound",
            measured_boundary: "prepare_plan_v1-entry-through-final-comparison-production-store-commit-and-outcome-return",
            fixture_boundary: "unique-Ed25519-signing-authentication-eligibility-and-budget-scope-provisioning-complete-before-measurement",
            warmup_operations: options.warmups,
            measured_operations: options.samples,
            concurrency: 1,
            canonical_commit_members: 8,
            connection_lifecycle: "production-store-opens-and-revalidates-a-bound-connection-per-phase",
            root_created_new: true,
            native_root_recorded: false,
            synthetic_values_public: true,
            signed_unique_plans: true,
            eligibility_precomputed_outside_samples: true,
            budget_scopes_preprovisioned_outside_samples: true,
            irreversible_recovery_provider_calls,
            caller_deadlines: "exclusive-absolute-monotonic-now-plus-bounded-budget",
        },
        results: CoordinatorResultEvidenceV1 {
            duration_unit: "nanoseconds",
            raw_sorted_samples_ns: samples,
            p50_ns,
            p95_ns,
            p99_ns,
            max_ns,
            committed_operations: verification.committed_operations,
            final_store_generation: verification.store_generation,
            final_operation_generation: verification.operation_generation,
            final_budget_generation: verification.budget_generation,
            final_event_generation: verification.event_generation,
            quick_check_ok: true,
            foreign_keys_ok: true,
            close_reopen_verified: true,
            p95_limit_ns: P95_LIMIT_NS,
            p99_limit_ns: P99_LIMIT_NS,
            meets_p95_limit,
            meets_p99_limit,
        },
        recovery_transfer: RecoveryArtifactReferenceV1 {
            separate_artifact: true,
            artifact_sha256: recovery_artifact.sha256.clone(),
            artifact_bytes: recovery_artifact.bytes,
            included_in_coordinator_percentiles: false,
        },
        limitations: [
            "controlled-host point-in-time evidence only",
            "public synthetic providers drive the real production preparation path but confer no dispatch or adapter authority",
            "filesystem and at-rest assurances are bounded caller labels, not auto-detected authority",
            "acknowledged process commits are not power-loss, sector-loss, or F_FULLFSYNC evidence",
            "recovery transfer is a separate artifact and never enters coordinator percentiles",
        ],
    };
    let coordinator_artifact = write_new_evidence_v1(&paths.output, &evidence)?;
    println!(
        "PLAN-004 samples={} commits={} p50_ns={} p95_ns={} p99_ns={} max_ns={} coordinator_artifact_sha256={} recovery_artifact_sha256={}",
        options.samples,
        verification.committed_operations,
        p50_ns,
        p95_ns,
        p99_ns,
        max_ns,
        coordinator_artifact.sha256,
        recovery_artifact.sha256,
    );
    if !meets_p95_limit || !meets_p99_limit {
        return Err("controlled-host latency budget exceeded; evidence was retained".into());
    }
    Ok(())
}

impl SampleFixtureV1 {
    fn try_new(
        index: usize,
        signer: &BenchmarkPlanSignerV1,
        clock: ControlledBenchmarkClockV1,
        plan_deadline_monotonic_ms: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let sequence = u64::try_from(index)?;
        let signed = sign_plan_v1(plan_input_v1(sequence)?, signer)?;
        let canonical = signed.to_canonical_json()?;
        let authentic = decode_and_verify_plan(&canonical, &signer.resolver_v1())?;
        let case = build_controlled_benchmark_case_v1(
            authentic,
            clock,
            plan_deadline_monotonic_ms,
            sequence,
        )?;
        Ok(Self { case })
    }
}

fn plan_input_v1(sequence: u64) -> Result<PlanInputV1, Box<dyn Error>> {
    let mut nonce = [0xA4_u8; 16];
    nonce[8..].copy_from_slice(&sequence.to_be_bytes());
    Ok(PlanInputV1 {
        operation_id: format!("operation:benchmark-{sequence:016x}"),
        task_id: format!("task:benchmark-{sequence:016x}"),
        workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1.to_owned(),
        boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1.to_owned(),
        task_lease_digest: benchmark_digest_v1(b"task-lease", sequence),
        request_source_kind: RequestSourceKindV1::HumanRequestGrant,
        request_source_digest: benchmark_digest_v1(b"request-source", sequence),
        catalog_version: CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1.to_owned(),
        policy_version: CONTROLLED_BENCHMARK_POLICY_VERSION_V1.to_owned(),
        risk_level: RiskLevelV1::L2,
        target: ResourceRefV1::new(
            "vault-controlled-benchmark",
            ["Public", "Controlled", "Target.txt"],
        )?,
        precondition: FilePreconditionInputV1 {
            volume_id: "volume:controlled-benchmark".to_owned(),
            file_id: format!("file:benchmark-{sequence:016x}"),
            content_sha256: benchmark_digest_v1(b"precondition", sequence),
            byte_length: 7,
        },
        replacement_bytes: format!("after-{sequence:016x}\n").into_bytes(),
        replacement_media_type: "text/plain;charset=utf-8".to_owned(),
        recovery: RecoveryInputV1 {
            class: RecoveryClassV1::Irreversible,
            atomicity: AtomicityV1::NonAtomic,
            reserved_bytes: 0,
        },
        capability_report_digest: benchmark_digest_v1(b"capability-report", sequence),
        capability_observed_at_unix_ms: CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
        required_capabilities: vec![
            "filesystem.verify-by-handle".to_owned(),
            "filesystem.atomic-replace".to_owned(),
        ],
        budget: BudgetInputV1 {
            reservation_id: format!("budget:benchmark-{sequence:016x}"),
            currency_code: "EUR".to_owned(),
            price_table_id: "price-table:controlled-benchmark-v1".to_owned(),
            max_cost_micro_units: 0,
            action_limit: 1,
            egress_bytes_limit: 0,
        },
        issued_at_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1,
        expires_at_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
        nonce: Nonce128::from_bytes(nonce),
        instance_epoch: 1,
        fencing_epoch: 9,
    })
}

fn benchmark_digest_v1(domain: &[u8], sequence: u64) -> Sha256Digest {
    Sha256Digest::from_bytes(digest_parts_v1(domain, sequence))
}

fn initialize_coordinator_root_v1(
    root: &Path,
    clock: BenchmarkCoordinatorClockV1,
    resolver: BenchmarkPlanResolverV1,
    deadline_monotonic_ms: u64,
) -> Result<(BenchmarkStoreV1, CoordinatorRootIdentityEvidenceV1), Box<dyn Error>> {
    fs::create_dir(root).map_err(|_| "dedicated coordinator root creation failed")?;
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.to_path_buf(), BUSY_WAIT_MS)
        .map_err(|error| format!("coordinator root rejected with {}", error.code()))?;
    let store =
        SqliteCoordinatorStoreV1::open_or_create(config, clock, resolver, deadline_monotonic_ms)
            .map_err(|error| format!("coordinator initialization failed with {}", error.code()))?;
    let root_identity = store.root_identity_evidence();
    Ok((store, root_identity))
}

fn open_benchmark_connection_v1(database: &Path) -> Result<Connection, Box<dyn Error>> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_millis(BUSY_WAIT_MS))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA wal_autocheckpoint=0;
         PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA cell_size_check=ON;
         PRAGMA recursive_triggers=ON;",
    )?;
    verify_runtime_profile_v1(&connection)?;
    Ok(connection)
}

fn verify_runtime_profile_v1(connection: &Connection) -> Result<(), Box<dyn Error>> {
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let wal_autocheckpoint: i64 =
        connection.query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let cell_size_check: i64 =
        connection.query_row("PRAGMA cell_size_check", [], |row| row.get(0))?;
    let recursive_triggers: i64 =
        connection.query_row("PRAGMA recursive_triggers", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || wal_autocheckpoint != 0
        || foreign_keys != 1
        || trusted_schema != 0
        || cell_size_check != 1
        || recursive_triggers != 1
    {
        return Err("coordinator SQLite durability profile mismatch".into());
    }
    Ok(())
}

fn provision_scopes_v1(
    database: &Path,
    fixtures: &[SampleFixtureV1],
) -> Result<(), Box<dyn Error>> {
    let mut connection = open_benchmark_connection_v1(database)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for fixture in fixtures {
        let scope = fixture.case.budget_scope_v1();
        let total = scope.total_v1();
        transaction.execute(
            "INSERT INTO budget_scopes (
                 scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
                 currency_code, price_table_id, total_cost_micro_units, total_action_count,
                 total_egress_bytes, total_recovery_bytes, held_cost_micro_units,
                 held_action_count, held_egress_bytes, held_recovery_bytes,
                 provisioning_profile
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                       0, 0, 0, 0, 'TRUSTED_LEASE_V1')",
            params![
                scope.scope_id_v1().as_bytes().as_slice(),
                scope.task_lease_digest_v1().as_bytes().as_slice(),
                scope.allowance_binding_digest_v1().as_bytes().as_slice(),
                i64::try_from(scope.scope_generation_v1())?,
                scope.currency_code_v1(),
                scope.price_table_id_v1(),
                i64::try_from(total[0])?,
                i64::try_from(total[1])?,
                i64::try_from(total[2])?,
                i64::try_from(total[3])?,
            ],
        )?;
    }
    let final_generation = i64::try_from(fixtures.len())?;
    let updated = transaction.execute(
        "UPDATE coordinator_store_meta
         SET store_generation=?1, budget_generation=?1
         WHERE singleton=1 AND root_lifecycle_state='ACTIVE'
           AND store_generation=0 AND budget_generation=0",
        [final_generation],
    )?;
    if updated != 1 {
        return Err("benchmark scope metadata preprovision failed".into());
    }
    transaction.commit()?;
    Ok(())
}

fn commit_once_v1(
    store: &BenchmarkStoreV1,
    fixture: SampleFixtureV1,
    clock: &ControlledBenchmarkClockV1,
) -> Result<(u64, usize), Box<dyn Error>> {
    let caller_deadline_monotonic_ms = clock.deadline_after_ms_v1(SAMPLE_DEADLINE_BUDGET_MS)?;
    let started = Instant::now();
    let committed = fixture
        .case
        .prepare_once_v1(store, caller_deadline_monotonic_ms)?;
    let elapsed = u64::try_from(started.elapsed().as_nanos())?;
    Ok((elapsed, committed.recovery_provider_calls_v1()))
}

struct CoordinatorVerificationV1 {
    committed_operations: u64,
    store_generation: u64,
    operation_generation: u64,
    budget_generation: u64,
    event_generation: u64,
}

fn verify_reopened_coordinator_v1(
    coordinator_root: &Path,
    database: &Path,
    root_identity: CoordinatorRootIdentityEvidenceV1,
    clock: BenchmarkCoordinatorClockV1,
    resolver: BenchmarkPlanResolverV1,
    deadline_monotonic_ms: u64,
    expected: u64,
) -> Result<CoordinatorVerificationV1, Box<dyn Error>> {
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        coordinator_root.to_path_buf(),
        root_identity,
        BUSY_WAIT_MS,
    )
    .map_err(|error| format!("coordinator reopen config failed with {}", error.code()))?;
    let reopened =
        SqliteCoordinatorStoreV1::open_or_create(config, clock, resolver, deadline_monotonic_ms)
            .map_err(|error| format!("full production reopen failed with {}", error.code()))?;
    if reopened.operation_count() != expected || reopened.root_identity_evidence() != root_identity
    {
        return Err("full production reopen count or root identity mismatch".into());
    }
    drop(reopened);
    let connection = open_benchmark_connection_v1(database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    let connection = open_benchmark_connection_v1(database)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let foreign_key_violation = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
    if quick_check != "ok" || foreign_key_violation {
        return Err("reopened coordinator integrity verification failed".into());
    }
    let joined: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM prepared_operations operation
         JOIN operation_transitions transition ON transition.operation_id=operation.operation_id
         JOIN preparation_comparisons comparison ON comparison.operation_id=operation.operation_id
         JOIN budget_reservations reservation ON reservation.operation_id=operation.operation_id
         JOIN preparation_recovery_evidence recovery ON recovery.operation_id=operation.operation_id
         JOIN preparation_events event ON event.event_id=operation.current_event_id",
        [],
        |row| row.get(0),
    )?;
    let generations: (i64, i64, i64, i64) = connection.query_row(
        "SELECT store_generation, operation_generation, budget_generation, event_generation
         FROM coordinator_store_meta WHERE singleton=1 AND root_lifecycle_state='ACTIVE'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let joined = u64::try_from(joined)?;
    let decoded = CoordinatorVerificationV1 {
        committed_operations: joined,
        store_generation: u64::try_from(generations.0)?,
        operation_generation: u64::try_from(generations.1)?,
        budget_generation: u64::try_from(generations.2)?,
        event_generation: u64::try_from(generations.3)?,
    };
    if joined != expected
        || decoded.operation_generation == 0
        || decoded.budget_generation == 0
        || decoded.event_generation == 0
        || decoded.operation_generation > decoded.store_generation
        || decoded.budget_generation > decoded.store_generation
        || decoded.event_generation > decoded.store_generation
    {
        return Err("reopened coordinator count or generation mismatch".into());
    }
    Ok(decoded)
}

fn run_recovery_transfer_v1(
    root: &Path,
    immutable_commit: String,
    hardware: String,
    filesystem_assurance: String,
    at_rest_profile: String,
) -> Result<RecoveryTransferEvidenceV1, Box<dyn Error>> {
    let material = root.join("public-synthetic-recovery-material.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&material)
        .map_err(|_| "recovery material create-new failed")?;
    let chunk = vec![0x5A_u8; RECOVERY_CHUNK_BYTES];
    let started = Instant::now();
    let mut remaining = RECOVERY_TRANSFER_BYTES;
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let length = usize::try_from(remaining.min(RECOVERY_CHUNK_BYTES as u64))?;
        file.write_all(&chunk[..length])?;
        hasher.update(&chunk[..length]);
        remaining -= u64::try_from(length)?;
    }
    file.sync_all()?;
    drop(file);
    let write_sync_close_ns = u64::try_from(started.elapsed().as_nanos())?;
    let expected_sha256 = bytes_hex_v1(&hasher.finalize());

    let verify_started = Instant::now();
    let mut reopened = OpenOptions::new().read(true).open(&material)?;
    let mut reopened_hasher = Sha256::new();
    let mut buffer = vec![0_u8; RECOVERY_CHUNK_BYTES];
    loop {
        let read = reopened.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        reopened_hasher.update(&buffer[..read]);
    }
    let reopened_sha256 = bytes_hex_v1(&reopened_hasher.finalize());
    let reopen_verify_ns = u64::try_from(verify_started.elapsed().as_nanos())?;
    if reopened_sha256 != expected_sha256 {
        return Err("reopened recovery material digest mismatch".into());
    }
    let total_ns = write_sync_close_ns
        .checked_add(reopen_verify_ns)
        .ok_or("recovery duration overflow")?;
    let throughput_bytes_per_second = RECOVERY_TRANSFER_BYTES
        .checked_mul(1_000_000_000)
        .and_then(|bytes| bytes.checked_div(write_sync_close_ns.max(1)))
        .ok_or("recovery throughput overflow")?;
    Ok(RecoveryTransferEvidenceV1 {
        schema: RECOVERY_EVIDENCE_SCHEMA_V1,
        acceptance_id: ACCEPTANCE_ID,
        immutable_commit,
        hardware,
        filesystem_assurance,
        at_rest_profile,
        material_bytes: RECOVERY_TRANSFER_BYTES,
        chunk_bytes: RECOVERY_CHUNK_BYTES,
        write_sync_close_ns,
        reopen_verify_ns,
        total_ns,
        throughput_bytes_per_second,
        material_sha256: expected_sha256,
        reopened_sha256,
        root_created_new: true,
        native_root_recorded: false,
        included_in_coordinator_percentiles: false,
        evidence_class: "public-synthetic-recovery-transfer-not-production-compensability",
    })
}

fn parse_options_from<I>(arguments: I) -> Result<Options, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut coordinator_root = None;
    let mut recovery_root = None;
    let mut output = None;
    let mut warmups = None;
    let mut samples = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--coordinator-root" => set_path_option_v1(
                "--coordinator-root",
                &mut coordinator_root,
                arguments.next(),
            )?,
            "--recovery-root" => {
                set_path_option_v1("--recovery-root", &mut recovery_root, arguments.next())?
            }
            "--output" => set_path_option_v1("--output", &mut output, arguments.next())?,
            "--warmups" => set_count_option_v1("--warmups", &mut warmups, arguments.next())?,
            "--samples" => set_count_option_v1("--samples", &mut samples, arguments.next())?,
            _ => return Err("unknown benchmark argument".into()),
        }
    }
    let warmups = warmups.ok_or("--warmups is required")?;
    let samples = samples.ok_or("--samples is required")?;
    if warmups < DEFAULT_WARMUPS {
        return Err("--warmups must be at least 500 for PLAN-004 evidence".into());
    }
    if samples < DEFAULT_SAMPLES {
        return Err("--samples must be at least 10000 for PLAN-004 evidence".into());
    }
    if warmups
        .checked_add(samples)
        .is_none_or(|total| total > MAX_TOTAL_OPERATIONS)
    {
        return Err("benchmark total operation count exceeds the bounded evidence limit".into());
    }
    Ok(Options {
        coordinator_root: coordinator_root.ok_or("--coordinator-root is required")?,
        recovery_root: recovery_root.ok_or("--recovery-root is required")?,
        output: output.ok_or("--output is required")?,
        warmups,
        samples,
    })
}

fn set_path_option_v1(
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

fn parse_count_v1(option: &str, value: Option<String>) -> Result<usize, Box<dyn Error>> {
    let value = value.ok_or_else(|| format!("{option} requires a positive integer"))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{option} must be greater than zero").into());
    }
    Ok(parsed)
}

fn set_count_option_v1(
    option: &str,
    destination: &mut Option<usize>,
    value: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let parsed = parse_count_v1(option, value)?;
    if destination.replace(parsed).is_some() {
        return Err(format!("{option} may appear only once").into());
    }
    Ok(())
}

fn required_public_label(variable: &str) -> Result<String, Box<dyn Error>> {
    let label = std::env::var(variable).map_err(|_| format!("{variable} is required"))?;
    validate_public_label_v1(variable, &label)?;
    Ok(label)
}

#[cfg(target_os = "macos")]
fn require_physical_m4_v1() -> Result<String, Box<dyn Error>> {
    if std::env::consts::ARCH != "aarch64" {
        return Err("physical-M4 benchmark requires macOS arm64".into());
    }
    let processor = command_stdout_v1("sysctl", &["-n", "machdep.cpu.brand_string"])?;
    let model = command_stdout_v1("sysctl", &["-n", "hw.model"])?;
    validate_public_label_v1("detected processor", &processor)?;
    validate_public_label_v1("detected model", &model)?;
    if !processor.starts_with("Apple M4") || !model.starts_with("Mac") {
        return Err("physical-M4 benchmark requires a detected Apple M4 host".into());
    }
    Ok(format!("{processor}; model {model}"))
}

#[cfg(not(target_os = "macos"))]
fn require_physical_m4_v1() -> Result<String, Box<dyn Error>> {
    Err("physical-M4 benchmark requires macOS arm64".into())
}

fn validate_public_label_v1(variable: &str, label: &str) -> Result<(), Box<dyn Error>> {
    if label.is_empty()
        || label.len() > 160
        || label.trim() != label
        || label.chars().any(char::is_control)
        || label.contains(['/', '\\'])
    {
        return Err(format!("{variable} must be a trimmed, bounded, non-path public label").into());
    }
    Ok(())
}

struct EvidencePathsV1 {
    coordinator_root: PathBuf,
    recovery_root: PathBuf,
    output: PathBuf,
    recovery_output: PathBuf,
}

fn preflight_paths_v1(options: &Options) -> Result<EvidencePathsV1, Box<dyn Error>> {
    let coordinator_root = normalize_new_leaf_v1(&options.coordinator_root)?;
    let recovery_root = normalize_new_leaf_v1(&options.recovery_root)?;
    let output = normalize_new_leaf_v1(&options.output)?;
    let recovery_output = derived_recovery_output_v1(&output)?;
    if coordinator_root == recovery_root
        || coordinator_root.starts_with(&recovery_root)
        || recovery_root.starts_with(&coordinator_root)
    {
        return Err("coordinator and recovery roots must be distinct and non-nested".into());
    }
    for root in [&coordinator_root, &recovery_root] {
        match fs::symlink_metadata(root) {
            Ok(_) => return Err("benchmark roots must identify new paths".into()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err("benchmark root availability check failed".into()),
        }
        if output.starts_with(root) || recovery_output.starts_with(root) {
            return Err("evidence outputs must be outside both benchmark roots".into());
        }
    }
    for evidence in [&output, &recovery_output] {
        match fs::symlink_metadata(evidence) {
            Ok(_) => return Err("benchmark evidence outputs must identify new files".into()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err("benchmark evidence availability check failed".into()),
        }
    }
    Ok(EvidencePathsV1 {
        coordinator_root,
        recovery_root,
        output,
        recovery_output,
    })
}

fn derived_recovery_output_v1(output: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let stem = output
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or("--output requires a UTF-8 file name")?;
    Ok(output.with_file_name(format!("{stem}.recovery-transfer.json")))
}

fn normalize_absolute_v1(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
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

fn normalize_new_leaf_v1(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let normalized = normalize_absolute_v1(path)?;
    let leaf = normalized
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or("benchmark paths require a final component")?;
    let parent = normalized
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or("benchmark path parent unavailable")?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| "benchmark path parent must already exist and be accessible")?;
    if !fs::metadata(&canonical_parent)
        .map_err(|_| "benchmark path parent metadata unavailable")?
        .is_dir()
    {
        return Err("benchmark path parent must be a directory".into());
    }
    Ok(canonical_parent.join(leaf))
}

fn corpus_evidence_v1() -> Result<CorpusEvidenceV1, Box<dyn Error>> {
    require_digest_v1(CASES_BYTES, CASES_SHA256)?;
    require_digest_v1(EXPECTED_BYTES, EXPECTED_SHA256)?;
    require_digest_v1(BACKUP_SCHEMA_BYTES, BACKUP_SCHEMA_SHA256)?;
    require_digest_v1(PROVENANCE_SCHEMA_BYTES, PROVENANCE_SCHEMA_SHA256)?;
    require_digest_v1(RECOVERY_ROOT_SCHEMA_BYTES, RECOVERY_ROOT_SCHEMA_SHA256)?;
    require_digest_v1(
        RECOVERY_SNAPSHOT_SCHEMA_BYTES,
        RECOVERY_SNAPSHOT_SCHEMA_SHA256,
    )?;
    if bytes_hex_v1(&embedded_schema_v1_sha256()) != STORE_SCHEMA_SHA256 {
        return Err("embedded coordinator schema digest drift".into());
    }
    let cases: Value = serde_json::from_slice(CASES_BYTES)?;
    let case_count = cases
        .get("cases")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or("corpus cases are absent")?;
    let fault_boundary_count = cases
        .get("fault_boundaries")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or("corpus fault boundaries are absent")?;
    if case_count != 335 || fault_boundary_count != 123 {
        return Err("frozen corpus count mismatch".into());
    }
    Ok(CorpusEvidenceV1 {
        case_count,
        fault_boundary_count,
        cases_sha256: CASES_SHA256,
        expected_outcomes_sha256: EXPECTED_SHA256,
        coordinator_schema_sha256: STORE_SCHEMA_SHA256,
        backup_manifest_schema_sha256: BACKUP_SCHEMA_SHA256,
        provenance_attestation_schema_sha256: PROVENANCE_SCHEMA_SHA256,
        recovery_root_schema_sha256: RECOVERY_ROOT_SCHEMA_SHA256,
        recovery_snapshot_schema_sha256: RECOVERY_SNAPSHOT_SCHEMA_SHA256,
    })
}

fn require_digest_v1(bytes: &[u8], expected: &str) -> Result<(), Box<dyn Error>> {
    if sha256_hex_v1(bytes) != expected {
        return Err("reviewed benchmark input digest drift".into());
    }
    Ok(())
}

fn require_sqlite_pin_v1() -> Result<(), Box<dyn Error>> {
    let source_id = rusqlite::ffi::SQLITE_SOURCE_ID.to_str()?;
    if rusqlite::version() != BUNDLED_SQLITE_VERSION || source_id != BUNDLED_SQLITE_SOURCE_ID {
        return Err("bundled SQLite version/source ID drift".into());
    }
    Ok(())
}

fn rustc_evidence_v1() -> Result<RustcEvidenceV1, Box<dyn Error>> {
    let rendered = command_stdout_v1("rustc", &["--version", "--verbose"])?;
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
    Ok(RustcEvidenceV1 {
        version_line,
        release: field("release:")?,
        commit_hash: field("commit-hash:")?,
        commit_date: field("commit-date:")?,
        host: field("host:")?,
        llvm_version: field("LLVM version:")?,
    })
}

fn os_build_evidence_v1() -> Result<String, Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        let version = command_stdout_v1("sw_vers", &["-productVersion"])?;
        let build = command_stdout_v1("sw_vers", &["-buildVersion"])?;
        return Ok(format!("macOS {version} build {build}"));
    }
    #[cfg(target_os = "windows")]
    {
        return command_stdout_v1("cmd", &["/C", "ver"]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return command_stdout_v1("uname", &["-sr"]);
    }
    #[allow(unreachable_code)]
    Ok(std::env::consts::OS.to_owned())
}

fn clean_git_commit_v1() -> Result<String, Box<dyn Error>> {
    let repository = env!("CARGO_MANIFEST_DIR");
    let commit = command_stdout_v1("git", &["-C", repository, "rev-parse", "HEAD"])?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("git did not return a full lowercase commit ID".into());
    }
    let status = command_stdout_v1(
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

fn require_same_clean_git_commit_v1(expected: &str) -> Result<(), Box<dyn Error>> {
    let observed = clean_git_commit_v1()?;
    if observed != expected {
        return Err("benchmark source commit changed during the controlled run".into());
    }
    Ok(())
}

fn command_stdout_v1(program: &str, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err("benchmark metadata command failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct WrittenArtifactV1 {
    sha256: String,
    bytes: u64,
}

fn write_new_evidence_v1<T: Serialize>(
    path: &Path,
    evidence: &T,
) -> Result<WrittenArtifactV1, Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(evidence)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(WrittenArtifactV1 {
        sha256: sha256_hex_v1(&bytes),
        bytes: u64::try_from(bytes.len())?,
    })
}

fn percentile_v1(sorted: &[u64], percent: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn digest_parts_v1(domain: &[u8], sequence: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"HELIXOS\0PLAN-004-BENCHMARK\0V1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(sequence.to_be_bytes());
    hasher.finalize().into()
}

fn sha256_hex_v1(bytes: &[u8]) -> String {
    bytes_hex_v1(&Sha256::digest(bytes))
}

fn bytes_hex_v1(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root_v1(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "helixos-t077-{label}-{}-{ordinal}",
                std::process::id()
            ))
    }

    fn exact_arguments() -> Vec<String> {
        [
            "--coordinator-root",
            "/tmp/plan004-coordinator",
            "--recovery-root",
            "/tmp/plan004-recovery",
            "--warmups",
            "500",
            "--samples",
            "10000",
            "--output",
            "/tmp/plan004-benchmark.json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn exact_quickstart_cli_and_minima_are_accepted() {
        let options = parse_options_from(exact_arguments()).expect("exact CLI parses");
        assert_eq!(options.warmups, 500);
        assert_eq!(options.samples, 10_000);
        assert_eq!(
            derived_recovery_output_v1(&options.output).unwrap(),
            PathBuf::from("/tmp/plan004-benchmark.recovery-transfer.json")
        );
    }

    #[test]
    fn below_minimum_duplicate_unknown_and_overflowing_counts_refuse() {
        let mut below = exact_arguments();
        below[5] = "499".to_owned();
        assert!(parse_options_from(below).is_err());

        let mut duplicate = exact_arguments();
        duplicate.extend(["--samples".to_owned(), "10000".to_owned()]);
        assert!(parse_options_from(duplicate).is_err());

        let mut unknown = exact_arguments();
        unknown.extend(["--root".to_owned(), "/tmp/unknown".to_owned()]);
        assert!(parse_options_from(unknown).is_err());

        let mut excessive = exact_arguments();
        excessive[7] = "100000".to_owned();
        assert!(parse_options_from(excessive).is_err());
    }

    #[test]
    fn labels_are_bounded_non_path_values_and_percentiles_are_nearest_rank() {
        validate_public_label_v1("LABEL", "public-mac-mini-m4").unwrap();
        assert!(validate_public_label_v1("LABEL", " private").is_err());
        assert!(validate_public_label_v1("LABEL", "private/path").is_err());
        assert_eq!(percentile_v1(&[1, 2, 3, 4, 5], 50), 3);
        assert_eq!(percentile_v1(&[1, 2, 3, 4, 5], 95), 5);
        assert_eq!(percentile_v1(&[1, 2, 3, 4, 5], 99), 5);
    }

    #[test]
    fn path_preflight_canonicalizes_existing_parents_without_creating_outputs() {
        let coordinator_root = test_root_v1("path-coordinator");
        let recovery_root = test_root_v1("path-recovery");
        let output = test_root_v1("path-output").with_extension("json");
        let options = Options {
            coordinator_root: coordinator_root.clone(),
            recovery_root: recovery_root.clone(),
            output: output.clone(),
            warmups: DEFAULT_WARMUPS,
            samples: DEFAULT_SAMPLES,
        };
        let paths = preflight_paths_v1(&options).unwrap();
        assert!(paths.coordinator_root.is_absolute());
        assert!(paths.recovery_root.is_absolute());
        assert!(paths.output.is_absolute());
        assert!(!coordinator_root.exists());
        assert!(!recovery_root.exists());
        assert!(!output.exists());
        assert!(!paths.recovery_output.exists());
    }

    #[test]
    fn fixtures_use_deterministic_unique_signed_plans_and_scope_bindings() {
        let signer = BenchmarkPlanSignerV1::new();
        let first_signed = sign_plan_v1(plan_input_v1(1).unwrap(), &signer).unwrap();
        let repeat_signed = sign_plan_v1(plan_input_v1(1).unwrap(), &signer).unwrap();
        let second_signed = sign_plan_v1(plan_input_v1(2).unwrap(), &signer).unwrap();
        assert_eq!(first_signed.plan_id(), repeat_signed.plan_id());
        assert_eq!(
            first_signed.to_canonical_json().unwrap(),
            repeat_signed.to_canonical_json().unwrap()
        );
        assert_ne!(first_signed.plan_id(), second_signed.plan_id());

        let clock = ControlledBenchmarkClockV1::start_v1();
        let deadline = clock.deadline_after_ms_v1(60_000).unwrap();
        let first = SampleFixtureV1::try_new(1, &signer, clock.clone(), deadline).unwrap();
        let second = SampleFixtureV1::try_new(2, &signer, clock, deadline).unwrap();
        assert_ne!(
            first.case.budget_scope_v1().scope_id_v1(),
            second.case.budget_scope_v1().scope_id_v1()
        );
        assert_ne!(
            first.case.budget_scope_v1().task_lease_digest_v1(),
            second.case.budget_scope_v1().task_lease_digest_v1()
        );
    }

    #[test]
    fn two_samples_use_production_prepare_commit_and_full_store_reopen() {
        let root = test_root_v1("production-smoke");
        let database = root.join("coordinator.sqlite3");
        let clock = ControlledBenchmarkClockV1::start_v1();
        let coordinator_clock = BenchmarkCoordinatorClockV1(clock.clone());
        let signer = BenchmarkPlanSignerV1::new();
        let resolver = signer.resolver_v1();
        let (store, root_identity) = initialize_coordinator_root_v1(
            &root,
            coordinator_clock.clone(),
            resolver.clone(),
            clock.deadline_after_ms_v1(60_000).unwrap(),
        )
        .unwrap();
        let eligibility_deadline = clock.deadline_after_ms_v1(60_000).unwrap();
        let fixtures = vec![
            SampleFixtureV1::try_new(1, &signer, clock.clone(), eligibility_deadline).unwrap(),
            SampleFixtureV1::try_new(2, &signer, clock.clone(), eligibility_deadline).unwrap(),
        ];
        provision_scopes_v1(&database, &fixtures).unwrap();
        for fixture in fixtures {
            let (_, provider_calls) = commit_once_v1(&store, fixture, &clock).unwrap();
            assert_eq!(provider_calls, 0);
        }
        drop(store);
        let verification = verify_reopened_coordinator_v1(
            &root,
            &database,
            root_identity,
            coordinator_clock,
            resolver,
            clock.deadline_after_ms_v1(60_000).unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(verification.committed_operations, 2);
        fs::remove_dir_all(root).unwrap();
    }
}
