//! Local diagnostic benchmark for the PLAN-005 durable no-effect dispatch path.
//!
//! Fixture construction and genuine PLAN-004 preparation happen before measurement.
//! Each timed repetition then crosses the production coordinator final-guard/commit,
//! durable handoff, independent adapter receive/consume, signed receipt, and exact
//! coordinator receipt-commit boundaries. This executable deliberately makes no
//! physical-M4 or PLAN-005 acceptance claim; T091 owns that controlled evidence run.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

#[cfg(not(feature = "controlled-benchmark"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("durable_dispatch_benchmark requires --features controlled-benchmark".into())
}

#[cfg(feature = "controlled-benchmark")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    benchmark::run()
}

#[cfg(feature = "controlled-benchmark")]
mod benchmark {
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_contracts::{
        decode_and_verify_plan, sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError,
        Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128, PlanInputV1,
        RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1,
        Result as ContractResult, RiskLevelV1, Sha256Digest as PlanSha256Digest,
    };
    use helix_coordinator_sqlite::{
        embedded_schema_v1_sha256, CoordinatorClockUnavailableV1,
        CoordinatorDispatchHandoffOutcomeV1, CoordinatorMonotonicClockV1,
        CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptEffectiveStateV1,
        CoordinatorReceiptLookupV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
        SqliteCoordinatorStoreV1, SqliteCoordinatorStoreV2,
    };
    use helix_dispatch_contracts::{
        ContractError as DispatchContractError, Generation, GrantKeyResolver, GrantSigner,
        GrantVerificationKeyV1, Identifier, ReceiptKeyResolver, ReceiptSigner,
        ReceiptVerificationKeyV1, RecoveryModeV1, Result as DispatchContractResult, SafeU64,
        Sha256Digest,
    };
    use helix_dispatch_inbox_sqlite::{
        AdapterClockObservationV1, AdapterClockV1, AdapterConsumptionAdmissionObservationV1,
        AdapterConsumptionAdmissionObserverV1, AdapterInboxConsumeOutcomeV1,
        AdapterInboxInitializationV1, AdapterInboxProfileV1, AdapterInboxReceiveOutcomeV1,
        AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1,
        AdapterReceiptEntropyDomainV1, AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1,
        AdapterReceiptSigningProfileV1, AdapterTimeSampleV1, EpochObservationV1,
        ReceivedInboxGrantV1, SqliteDispatchInboxStoreV1, SupervisorEpochObservationV1,
        SupervisorEpochObserverV1,
    };
    use helix_plan_dispatch::{
        dispatch_prepared_once_v1, DispatchAttemptIdV1, DispatchAuthorityCaptureOutcomeV1,
        DispatchAuthorityCapturePhaseV1, DispatchAuthorityProviderV1, DispatchAuthorityViewInputV1,
        DispatchAuthorityViewV1, DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1,
        DispatchCommitResolutionV1, DispatchEntropyDomainV1, DispatchEntropyErrorV1,
        DispatchEntropySourceV1, DispatchGuardAcquisitionV1, DispatchGuardClassV1,
        DispatchGuardOrderErrorV1, DispatchGuardProviderV1, DispatchGuardSetV1,
        DispatchGuardValidationV1, DispatchHandoffGuardV1, DispatchHandoffOutcomeV1,
        DispatchHandoffValidationV1, DispatchLookupRequestInputV1, DispatchLookupRequestV1,
        DispatchRequestOutcomeV1, DispatchStoreCommitClassificationV1, DispatchTransportV1,
        DISPATCH_AUTHORITY_VIEW_VERSION_V1, DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
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
    use sha2::{Digest as _, Sha256};
    use std::error::Error;
    use std::fmt;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const EVIDENCE_SCHEMA_V1: &str = "helixos.durable-dispatch-benchmark/3";
    const ACCEPTANCE_ID: &str = "PLAN-005-SC-005";
    const WARMUP_OPERATIONS: usize = 500;
    const MEASURED_OPERATIONS: usize = 10_000;
    const TOTAL_OPERATIONS: usize = WARMUP_OPERATIONS + MEASURED_OPERATIONS;
    const BUSY_WAIT_MS: u64 = 30_000;
    const INITIALIZATION_DEADLINE_MS: u64 = 60_000;
    const PREPARATION_RUN_WINDOW_MS: u64 = 12 * 60 * 60 * 1_000;
    const DISPATCH_LIFETIME_MS: u64 = 5_000;
    const P95_REFERENCE_LIMIT_NS: u64 = 50_000_000;
    const P99_REFERENCE_LIMIT_NS: u64 = 100_000_000;
    const COORDINATOR_DATABASE_FILENAME: &str = "coordinator.sqlite3";
    const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";
    const DESTINATION_ADAPTER_ID: &str = "adapter:t084:no-effect-v1";
    const DISPATCH_SIGNER_KEY_ID: &str = "dispatch-key:t084-v1";
    const RECEIPT_SIGNER_KEY_ID: &str = "receipt-key:t084-v1";
    const PLAN_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];
    const DISPATCH_SIGNING_KEY_BYTES: [u8; 32] = [0x84; 32];
    const RECEIPT_SIGNING_KEY_BYTES: [u8; 32] = [0x85; 32];
    const RECEIPT_SIGNER_PROFILE_DIGEST: [u8; 32] = [0x86; 32];
    const ADAPTER_CAPABILITY_DIGEST: [u8; 32] = [0x87; 32];
    const CONTROLLED_BASE_MONOTONIC_MS: u64 = 1_000_000;
    const CONTROLLED_BASE_UTC_MS: u64 = CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 + 10_000;
    const BENCHMARK_CORPUS_DOMAIN_V1: &[u8] = b"HELIXOS\0T084-CANONICAL-PLAN-CORPUS\0V1\0";
    const V2_OVERLAY: &str = include_str!(
        "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
    );
    const ADAPTER_INBOX_SCHEMA_V1: &[u8] =
        include_bytes!("../../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql");
    #[cfg(test)]
    const EXPECTED_ADAPTER_INBOX_SCHEMA_V1_SHA256: [u8; 32] = [
        0xf6, 0xd4, 0x91, 0x71, 0x75, 0x03, 0x8f, 0xf7, 0x26, 0xec, 0x6d, 0x27, 0xa1, 0xc5, 0x9d,
        0xe7, 0x21, 0x0f, 0x58, 0xa1, 0x07, 0x9c, 0xf4, 0x28, 0x58, 0x61, 0x30, 0x86, 0x2c, 0x05,
        0x07, 0x24,
    ];
    const CORPUS_CASES: &[u8] =
        include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
    const CORPUS_EXPECTED: &[u8] =
        include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json");
    const CORPUS_FAULT_BOUNDARIES: &[u8] =
        include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/fault-boundaries.json");

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, PartialEq, Eq)]
    struct OptionsV1 {
        output: PathBuf,
        warmups: usize,
        samples: usize,
    }

    #[derive(Serialize)]
    struct EvidenceV1 {
        schema: &'static str,
        acceptance_reference: &'static str,
        claim: ClaimV1,
        environment: EnvironmentV1,
        artifact: ArtifactV1,
        schemas: SchemasV1,
        corpus: CorpusV1,
        stores: StoresV1,
        workload: WorkloadV1,
        characterization: CharacterizationV1,
        results: ResultsV1,
    }

    #[derive(Serialize)]
    struct ClaimV1 {
        evidence_class: &'static str,
        diagnostic_only: bool,
        physical_m4_claim: bool,
        acceptance_gate_evaluated: bool,
        limitation: &'static str,
    }

    #[derive(Serialize)]
    struct EnvironmentV1 {
        hardware: String,
        memory_bytes: String,
        os: String,
        filesystem_type: String,
        filesystem_assurance: String,
        architecture: &'static str,
        rust_toolchain: String,
        cargo_profile: &'static str,
        cargo_features: Vec<&'static str>,
        available_parallelism: usize,
    }

    #[derive(Serialize)]
    struct ArtifactV1 {
        executable_sha256: String,
        source_sha256: String,
        cargo_lock_sha256: String,
    }

    struct FilesystemProbeV1 {
        filesystem_type: String,
        assurance: String,
    }

    #[derive(Serialize)]
    struct SchemasV1 {
        coordinator_base_v1_sha256: String,
        coordinator_dispatch_v2_sha256: String,
        adapter_inbox_v1_sha256: String,
    }

    #[derive(Serialize)]
    struct CorpusV1 {
        benchmark_canonical_plans_sha256: String,
        benchmark_document_count: usize,
        benchmark_framing: &'static str,
        contract_cases_sha256: String,
        contract_expected_outcomes_sha256: String,
        contract_fault_boundaries_sha256: String,
    }

    #[derive(Serialize)]
    struct StoresV1 {
        coordinator: StoreProfileV1,
        adapter: StoreProfileV1,
    }

    #[derive(Serialize)]
    struct StoreProfileV1 {
        application_id: i64,
        schema_version: i64,
        sqlite_version: String,
        sqlite_source_id: String,
        journal_mode: String,
        synchronous: i64,
        wal_autocheckpoint_pages: i64,
        foreign_keys: i64,
        trusted_schema: i64,
        cell_size_check: i64,
        recursive_triggers: i64,
        busy_wait_ms: u64,
    }

    #[derive(Serialize)]
    struct WorkloadV1 {
        name: &'static str,
        measured_boundary: &'static str,
        preparation_boundary: &'static str,
        store_lifecycle: &'static str,
        setup_schedule: &'static str,
        fixture_corpus: &'static str,
        warmup_operations: usize,
        measured_operations: usize,
        total_unique_operations: usize,
        concurrency: usize,
        coordinator_ordinary_queue_capacity: i64,
        coordinator_control_queue_capacity: i64,
        adapter_ordinary_queue_capacity: i64,
        queue_depth_at_each_new_dispatch: usize,
        retained_preparations_per_coordinator_root: usize,
        retained_grants_per_adapter_root: usize,
        grant_lifetime_ms: u64,
        possible_handoff_readback_claim_included: bool,
        nominal_wal_full_commit_count: usize,
        acknowledged_attempt_bound_in_receipt_transaction: bool,
        production_coordinator_store: bool,
        production_adapter_store: bool,
        real_adapter_receive_consume: bool,
        no_effect_surface: bool,
        raw_sample_order: &'static str,
    }

    #[derive(Serialize)]
    struct ResultsV1 {
        duration_unit: &'static str,
        count: usize,
        raw_samples_ns: Vec<u64>,
        p50_ns: u64,
        p95_ns: u64,
        p99_ns: u64,
        max_ns: u64,
        reference_p95_limit_ns: u64,
        reference_p99_limit_ns: u64,
        reference_limits_are_acceptance_verdict: bool,
        committed_executing_receipts: usize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    struct PhaseSampleV1 {
        final_guard_to_dispatch_commit_ns: u64,
        dispatch_commit_to_handoff_ack_ns: u64,
        handoff_ack_to_adapter_consumed_ns: u64,
        adapter_consumed_to_coordinator_receipt_commit_ns: u64,
        total_ns: u64,
    }

    impl PhaseSampleV1 {
        fn try_from_cumulative_v1(cumulative_ns: [u64; 4]) -> Result<Self, &'static str> {
            let [dispatch, handoff, consumed, receipt] = cumulative_ns;
            let dispatch_to_handoff = handoff
                .checked_sub(dispatch)
                .ok_or("handoff boundary preceded dispatch commit")?;
            let handoff_to_consumed = consumed
                .checked_sub(handoff)
                .ok_or("adapter consumption preceded handoff acknowledgement")?;
            let consumed_to_receipt = receipt
                .checked_sub(consumed)
                .ok_or("coordinator receipt commit preceded adapter consumption")?;
            let partition = dispatch
                .checked_add(dispatch_to_handoff)
                .and_then(|value| value.checked_add(handoff_to_consumed))
                .and_then(|value| value.checked_add(consumed_to_receipt))
                .ok_or("phase characterization overflowed")?;
            if partition != receipt {
                return Err("phase characterization did not partition the total");
            }
            Ok(Self {
                final_guard_to_dispatch_commit_ns: dispatch,
                dispatch_commit_to_handoff_ack_ns: dispatch_to_handoff,
                handoff_ack_to_adapter_consumed_ns: handoff_to_consumed,
                adapter_consumed_to_coordinator_receipt_commit_ns: consumed_to_receipt,
                total_ns: receipt,
            })
        }

        fn partition_is_exact_v1(self) -> bool {
            self.final_guard_to_dispatch_commit_ns
                .checked_add(self.dispatch_commit_to_handoff_ack_ns)
                .and_then(|value| value.checked_add(self.handoff_ack_to_adapter_consumed_ns))
                .and_then(|value| {
                    value.checked_add(self.adapter_consumed_to_coordinator_receipt_commit_ns)
                })
                == Some(self.total_ns)
        }
    }

    #[derive(Serialize)]
    struct CharacterizationV1 {
        clock: &'static str,
        boundary_order: [&'static str; 5],
        sample_count: usize,
        every_sample_exactly_partitions_total: bool,
        summaries: PhaseSummariesV1,
        raw_samples: Vec<PhaseSampleV1>,
    }

    #[derive(Serialize)]
    struct PhaseSummariesV1 {
        final_guard_to_dispatch_commit: PhaseSummaryV1,
        dispatch_commit_to_handoff_ack: PhaseSummaryV1,
        handoff_ack_to_adapter_consumed: PhaseSummaryV1,
        adapter_consumed_to_coordinator_receipt_commit: PhaseSummaryV1,
    }

    #[derive(Serialize)]
    struct PhaseSummaryV1 {
        p50_ns: u64,
        p95_ns: u64,
        p99_ns: u64,
        max_ns: u64,
    }

    struct SampleFixtureV1 {
        case: ControlledBenchmarkCaseV1,
        canonical_plan: Vec<u8>,
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
        fn new_v1() -> Self {
            Self {
                key: SigningKey::from_bytes(&PLAN_SIGNING_KEY_BYTES),
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
    type BenchmarkStoreV2 =
        SqliteCoordinatorStoreV2<BenchmarkCoordinatorClockV1, BenchmarkPlanResolverV1>;

    #[derive(Clone)]
    struct PreparedDispatchBindingsV1 {
        operation_id: String,
        preparation_attempt_id: [u8; 32],
        plan_id: [u8; 32],
        preparation_transition_generation: u64,
        task_id: String,
        workload_id: String,
        boot_id: String,
        instance_epoch: u64,
        supervisor_epoch: u64,
        reservation_id: String,
        task_lease_digest: [u8; 32],
        recovery_mode: RecoveryModeV1,
    }

    impl fmt::Debug for PreparedDispatchBindingsV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("PreparedDispatchBindingsV1")
                .finish_non_exhaustive()
        }
    }

    impl PreparedDispatchBindingsV1 {
        fn lookup_request_v1(&self, deadline_monotonic_ms: u64) -> DispatchLookupRequestV1 {
            DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
                contract_version: DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
                operation_id: &self.operation_id,
                expected_plan_digest: self.plan_id,
                expected_preparation_attempt_digest: self.preparation_attempt_id,
                expected_preparation_transition_generation: self.preparation_transition_generation,
                caller_deadline_monotonic_ms: deadline_monotonic_ms,
            })
            .expect("T084 prepared lookup is valid")
        }
    }

    #[derive(Clone)]
    struct AuthorityFixtureV1 {
        prepared: PreparedDispatchBindingsV1,
        sampled_monotonic_ms: u64,
        sampled_utc_ms: u64,
        deadline_monotonic_ms: u64,
        benchmark_interval: BenchmarkIntervalV1,
    }

    #[derive(Clone, Default)]
    struct BenchmarkIntervalV1 {
        started: Arc<OnceLock<Instant>>,
    }

    impl BenchmarkIntervalV1 {
        fn start_at_final_guard_entry_v1(&self) -> Result<(), ()> {
            self.started.set(Instant::now()).map_err(|_| ())
        }

        fn elapsed_until_v1(&self, ended: Instant) -> Result<u64, Box<dyn Error>> {
            let started = self
                .started
                .get()
                .ok_or("final-guard benchmark interval did not start")?;
            Ok(u64::try_from(ended.duration_since(*started).as_nanos())?)
        }
    }

    impl AuthorityFixtureV1 {
        fn view_v1(&self, phase: DispatchAuthorityCapturePhaseV1) -> DispatchAuthorityViewV1 {
            DispatchAuthorityViewV1::try_new(DispatchAuthorityViewInputV1 {
                contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
                phase,
                time: helix_plan_dispatch::DispatchTimeCaptureV1::new(
                    identifier_v1(&self.prepared.boot_id),
                    generation_v1(1),
                    safe_v1(self.sampled_utc_ms),
                    safe_v1(self.sampled_monotonic_ms),
                ),
                task_id: identifier_v1(&self.prepared.task_id),
                workload_id: identifier_v1(&self.prepared.workload_id),
                instance_epoch: safe_v1(self.prepared.instance_epoch),
                supervisor_epoch: safe_v1(self.prepared.supervisor_epoch),
                supervisor_generation: generation_v1(1),
                trust_generation: generation_v1(1),
                verified_key_fingerprint: digest_byte_v1(1),
                workload_generation: generation_v1(1),
                workload_evidence_digest: digest_byte_v1(2),
                lease_generation: generation_v1(1),
                lease_digest: Sha256Digest::from_bytes(self.prepared.task_lease_digest),
                lease_decision_digest: digest_byte_v1(3),
                authorization_generation: generation_v1(1),
                authorization_evidence_digest: digest_byte_v1(4),
                policy_generation: generation_v1(1),
                policy_decision_generation: generation_v1(1),
                policy_content_digest: digest_byte_v1(5),
                policy_decision_digest: digest_byte_v1(6),
                catalogue_generation: generation_v1(1),
                catalogue_decision_generation: generation_v1(1),
                catalogue_content_digest: digest_byte_v1(7),
                catalogue_decision_digest: digest_byte_v1(8),
                capability_report_generation: generation_v1(1),
                capability_report_digest: digest_byte_v1(9),
                host_driver_context_digest: digest_byte_v1(10),
                capability_observed_at_utc_ms: safe_v1(self.sampled_utc_ms),
                capability_max_age_ms: safe_v1(DISPATCH_LIFETIME_MS),
                adapter_capability_digest: Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
                replay_claim_id: digest_byte_v1(11),
                replay_claimant_generation: generation_v1(1),
                replay_binding_digest: digest_byte_v1(12),
                budget_scope_id: identifier_v1("scope:t084-v1"),
                budget_scope_generation: generation_v1(1),
                budget_scope_binding_digest: digest_byte_v1(13),
                reservation_id: identifier_v1(&self.prepared.reservation_id),
                reservation_generation: generation_v1(1),
                reservation_binding_digest: digest_byte_v1(14),
                reservation_vector_digest: digest_byte_v1(15),
                recovery_reference_digest: digest_byte_v1(16),
                recovery_mode: self.prepared.recovery_mode,
                recovery_profile_digest: digest_byte_v1(17),
                recovery_binding_digest: digest_byte_v1(18),
                recovery_receipt_digest: digest_byte_v1(19),
                destination_adapter_id: identifier_v1(DESTINATION_ADAPTER_ID),
                protocol_version: 1,
                signer_key_id: identifier_v1(DISPATCH_SIGNER_KEY_ID),
                signer_generation: generation_v1(1),
                signer_profile_digest: dispatch_key_fingerprint_v1(),
                earliest_authority_deadline_monotonic_ms: generation_v1(self.deadline_monotonic_ms),
            })
            .expect("T084 coherent dispatch authority constructs")
        }
    }

    impl DispatchAuthorityProviderV1 for AuthorityFixtureV1 {
        fn capture_authority_v1(
            &self,
            phase: DispatchAuthorityCapturePhaseV1,
            _request: &DispatchLookupRequestV1,
            _attempt: &DispatchAttemptIdV1,
        ) -> DispatchAuthorityCaptureOutcomeV1 {
            DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(self.view_v1(phase)))
        }
    }

    struct GuardSetV1 {
        authority: AuthorityFixtureV1,
    }

    impl DispatchGuardSetV1 for GuardSetV1 {
        type Permit = PermitV1;

        fn capture_final_authority_v1(&mut self) -> DispatchAuthorityCaptureOutcomeV1 {
            DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(
                self.authority
                    .view_v1(DispatchAuthorityCapturePhaseV1::FinalGuarded),
            ))
        }

        fn validate_all_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
            if now_monotonic_ms < self.authority.deadline_monotonic_ms {
                DispatchGuardValidationV1::Valid
            } else {
                DispatchGuardValidationV1::DeadlineReached
            }
        }

        fn acquire_commit_permit_v1(
            &mut self,
            _attempt: &DispatchAttemptIdV1,
            deadline_monotonic_ms: u64,
        ) -> DispatchCommitPermitOutcomeV1<Self::Permit> {
            DispatchCommitPermitOutcomeV1::Permitted(PermitV1 {
                deadline_monotonic_ms,
            })
        }

        fn release_reverse_v1(self) {}
    }

    impl DispatchGuardProviderV1 for AuthorityFixtureV1 {
        type GuardSet = GuardSetV1;

        fn acquire_in_fixed_order_v1(
            &self,
            _request: &DispatchLookupRequestV1,
            _attempt: &DispatchAttemptIdV1,
            after_acquisition: &mut dyn FnMut(
                DispatchGuardClassV1,
            ) -> Result<(), DispatchGuardOrderErrorV1>,
        ) -> DispatchGuardAcquisitionV1<Self::GuardSet> {
            if self
                .benchmark_interval
                .start_at_final_guard_entry_v1()
                .is_err()
            {
                return DispatchGuardAcquisitionV1::OrderViolated;
            }
            for class in DispatchGuardClassV1::acquisition_order() {
                if after_acquisition(class).is_err() {
                    return DispatchGuardAcquisitionV1::OrderViolated;
                }
            }
            DispatchGuardAcquisitionV1::Acquired(GuardSetV1 {
                authority: self.clone(),
            })
        }
    }

    struct PermitV1 {
        deadline_monotonic_ms: u64,
    }

    impl DispatchCommitPermitV1 for PermitV1 {
        fn deadline_monotonic_ms(&self) -> u64 {
            self.deadline_monotonic_ms
        }

        fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
            if now_monotonic_ms < self.deadline_monotonic_ms {
                DispatchGuardValidationV1::Valid
            } else {
                DispatchGuardValidationV1::DeadlineReached
            }
        }

        fn commit_once<C, U, F>(self, commit: F) -> DispatchCommitResolutionV1<C, U>
        where
            C: Send,
            U: Send,
            F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>,
        {
            match commit() {
                DispatchStoreCommitClassificationV1::Committed(receipt) => {
                    DispatchCommitResolutionV1::Committed(receipt)
                }
                DispatchStoreCommitClassificationV1::PriorExactDispatch(receipt) => {
                    DispatchCommitResolutionV1::PriorExactDispatch(receipt)
                }
                DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                    DispatchCommitResolutionV1::ConfirmedRollback
                }
                DispatchStoreCommitClassificationV1::Uncertain(custody) => {
                    DispatchCommitResolutionV1::Uncertain(custody)
                }
                DispatchStoreCommitClassificationV1::Conflict => {
                    DispatchCommitResolutionV1::Conflict
                }
                DispatchStoreCommitClassificationV1::Unavailable => {
                    DispatchCommitResolutionV1::Unavailable
                }
                DispatchStoreCommitClassificationV1::Unhealthy
                | DispatchStoreCommitClassificationV1::Unclassified => {
                    DispatchCommitResolutionV1::Unclassified
                }
            }
        }

        fn abandon_v1(self) {}
    }

    struct SeededDispatchEntropyV1(u64);

    impl DispatchEntropySourceV1 for SeededDispatchEntropyV1 {
        fn fill_entropy_v1(
            &self,
            domain: DispatchEntropyDomainV1,
            destination: &mut [u8],
        ) -> Result<(), DispatchEntropyErrorV1> {
            for (block, chunk) in destination.chunks_mut(32).enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(b"HELIXOS\0T084-DISPATCH-ENTROPY\0V1\0");
                hasher.update(self.0.to_be_bytes());
                hasher.update([dispatch_entropy_domain_tag_v1(domain)]);
                hasher.update((block as u64).to_be_bytes());
                let digest = hasher.finalize();
                chunk.copy_from_slice(&digest[..chunk.len()]);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct DispatchKeysV1 {
        signing_key: SigningKey,
    }

    impl DispatchKeysV1 {
        fn fixed_v1() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&DISPATCH_SIGNING_KEY_BYTES),
            }
        }
    }

    impl GrantSigner for DispatchKeysV1 {
        fn key_id(&self) -> &str {
            DISPATCH_SIGNER_KEY_ID
        }

        fn sign_execution_grant(&self, message: &[u8]) -> DispatchContractResult<[u8; 64]> {
            Ok(self.signing_key.sign(message).to_bytes())
        }
    }

    #[derive(Clone)]
    struct DispatchGrantResolverV1 {
        verifying_key: [u8; 32],
    }

    impl DispatchGrantResolverV1 {
        fn fixed_v1() -> Self {
            Self {
                verifying_key: SigningKey::from_bytes(&DISPATCH_SIGNING_KEY_BYTES)
                    .verifying_key()
                    .to_bytes(),
            }
        }
    }

    impl GrantKeyResolver for DispatchGrantResolverV1 {
        fn resolve_grant_key(
            &self,
            key_id: &str,
        ) -> DispatchContractResult<GrantVerificationKeyV1> {
            if key_id == DISPATCH_SIGNER_KEY_ID {
                Ok(GrantVerificationKeyV1::current(self.verifying_key))
            } else {
                Err(DispatchContractError::UnknownKey)
            }
        }
    }

    #[derive(Clone)]
    struct ReceiptKeysV1 {
        signing_key: SigningKey,
    }

    impl ReceiptKeysV1 {
        fn fixed_v1() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&RECEIPT_SIGNING_KEY_BYTES),
            }
        }
    }

    impl ReceiptSigner for ReceiptKeysV1 {
        fn key_id(&self) -> &str {
            RECEIPT_SIGNER_KEY_ID
        }

        fn sign_execution_receipt(&self, message: &[u8]) -> DispatchContractResult<[u8; 64]> {
            Ok(self.signing_key.sign(message).to_bytes())
        }
    }

    impl ReceiptKeyResolver for ReceiptKeysV1 {
        fn resolve_receipt_key(
            &self,
            key_id: &str,
        ) -> DispatchContractResult<ReceiptVerificationKeyV1> {
            if key_id == RECEIPT_SIGNER_KEY_ID {
                Ok(ReceiptVerificationKeyV1::current(
                    self.signing_key.verifying_key().to_bytes(),
                ))
            } else {
                Err(DispatchContractError::UnknownKey)
            }
        }
    }

    struct CoordinatorReceiptKeysV1 {
        grant: DispatchGrantResolverV1,
        receipt: ReceiptKeysV1,
    }

    impl GrantKeyResolver for CoordinatorReceiptKeysV1 {
        fn resolve_grant_key(
            &self,
            key_id: &str,
        ) -> DispatchContractResult<GrantVerificationKeyV1> {
            self.grant.resolve_grant_key(key_id)
        }
    }

    impl ReceiptKeyResolver for CoordinatorReceiptKeysV1 {
        fn resolve_receipt_key(
            &self,
            key_id: &str,
        ) -> DispatchContractResult<ReceiptVerificationKeyV1> {
            self.receipt.resolve_receipt_key(key_id)
        }
    }

    struct FixedAdapterClockV1 {
        boot_id: String,
        generation: u64,
        sampled_utc_ms: u64,
        sampled_monotonic_ms: u64,
    }

    impl FixedAdapterClockV1 {
        fn sample_v1(&self, generation: u64) -> AdapterTimeSampleV1 {
            AdapterTimeSampleV1::new(
                identifier_v1(&self.boot_id),
                generation_v1(generation),
                safe_v1(self.sampled_utc_ms),
                safe_v1(self.sampled_monotonic_ms),
            )
        }
    }

    impl AdapterClockV1 for FixedAdapterClockV1 {
        fn observe_time_v1(&self) -> AdapterClockObservationV1 {
            AdapterClockObservationV1::Current(self.sample_v1(self.generation))
        }
    }

    struct FreshAdapterEpochObserverV1 {
        connection: Mutex<Connection>,
        boot_id: String,
        supervisor_epoch: u64,
        sampled_utc_ms: u64,
        sampled_monotonic_ms: u64,
    }

    impl FreshAdapterEpochObserverV1 {
        fn open_v1(
            database: &Path,
            boot_id: String,
            supervisor_epoch: u64,
            sampled_utc_ms: u64,
            sampled_monotonic_ms: u64,
        ) -> Result<Self, Box<dyn Error>> {
            let connection = Connection::open_with_flags(
                database,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?;
            Ok(Self {
                connection: Mutex::new(connection),
                boot_id,
                supervisor_epoch,
                sampled_utc_ms,
                sampled_monotonic_ms,
            })
        }
    }

    impl SupervisorEpochObserverV1 for FreshAdapterEpochObserverV1 {
        fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
            let Ok(connection) = self.connection.lock() else {
                return SupervisorEpochObservationV1::Unavailable;
            };
            let Ok(watermark) = connection.query_row(
                "SELECT epoch_observer_generation FROM adapter_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            ) else {
                return SupervisorEpochObservationV1::Unreadable;
            };
            let Some(next) = u64::try_from(watermark)
                .ok()
                .and_then(|value| value.checked_add(1))
            else {
                return SupervisorEpochObservationV1::Stale;
            };
            let sample = AdapterTimeSampleV1::new(
                identifier_v1(&self.boot_id),
                generation_v1(next),
                safe_v1(self.sampled_utc_ms),
                safe_v1(self.sampled_monotonic_ms),
            );
            SupervisorEpochObservationV1::Current(EpochObservationV1::new(
                safe_v1(self.supervisor_epoch),
                generation_v1(next),
                sample,
            ))
        }
    }

    struct RunningAdmissionV1;

    impl AdapterConsumptionAdmissionObserverV1 for RunningAdmissionV1 {
        fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
            AdapterConsumptionAdmissionObservationV1::Running
        }
    }

    struct SeededReceiptEntropyV1(u64);

    impl AdapterReceiptEntropyV1 for SeededReceiptEntropyV1 {
        fn fill_receipt_entropy_v1(
            &self,
            domain: AdapterReceiptEntropyDomainV1,
            destination: &mut [u8; 32],
        ) -> Result<(), AdapterReceiptEntropyErrorV1> {
            if domain != AdapterReceiptEntropyDomainV1::ReceiptIdentity {
                return Err(AdapterReceiptEntropyErrorV1::Unsupported);
            }
            let mut hasher = Sha256::new();
            hasher.update(b"HELIXOS\0T084-RECEIPT-ENTROPY\0V1\0");
            hasher.update(self.0.to_be_bytes());
            destination.copy_from_slice(&hasher.finalize());
            Ok(())
        }
    }

    struct LiveHandoffGuardV1 {
        binding: [u8; 32],
        deadline_monotonic_ms: u64,
    }

    impl DispatchHandoffGuardV1 for LiveHandoffGuardV1 {
        fn evidence_binding_v1(&self) -> [u8; 32] {
            self.binding
        }

        fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
            if now_monotonic_ms < self.deadline_monotonic_ms {
                DispatchHandoffValidationV1::Live
            } else {
                DispatchHandoffValidationV1::DeadlineReached
            }
        }

        fn release_v1(self) {}
    }

    struct AdapterReceiveTransportV1<'store> {
        store: &'store SqliteDispatchInboxStoreV1,
        clock: &'store FixedAdapterClockV1,
        epoch_observer: &'store FreshAdapterEpochObserverV1,
        grant_resolver: DispatchGrantResolverV1,
    }

    impl DispatchTransportV1 for AdapterReceiveTransportV1<'_> {
        type Guard = LiveHandoffGuardV1;
        type Response = ReceivedInboxGrantV1;

        fn acquire_handoff_guard_v1(
            &self,
            grant_binding: &[u8; 32],
            deadline_monotonic_ms: u64,
        ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
            Ok(LiveHandoffGuardV1 {
                binding: *grant_binding,
                deadline_monotonic_ms,
            })
        }

        fn deliver_exact_v1(
            &self,
            _guard: &mut Self::Guard,
            exact_signed_grant_bytes: &[u8],
        ) -> DispatchHandoffOutcomeV1<Self::Response> {
            match self.store.receive_grant_v1(
                exact_signed_grant_bytes,
                &self.grant_resolver,
                self.clock,
                self.epoch_observer,
            ) {
                Ok(AdapterInboxReceiveOutcomeV1::Received(received)) => {
                    DispatchHandoffOutcomeV1::Acknowledged(received)
                }
                _ => DispatchHandoffOutcomeV1::PossibleHandoff,
            }
        }
    }

    struct TempRootV1 {
        path: PathBuf,
    }

    impl TempRootV1 {
        fn reserve_v1(kind: &str) -> Result<Self, Box<dyn Error>> {
            for _ in 0..32 {
                let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
                let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                let path = std::env::temp_dir().join(format!(
                    "helixos-t084-{kind}-{}-{nanos}-{sequence}",
                    std::process::id()
                ));
                if !path.exists() {
                    return Ok(Self { path });
                }
            }
            Err("unable to reserve a unique T084 benchmark root".into())
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRootV1 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        if cfg!(debug_assertions) {
            return Err("durable_dispatch_benchmark must be run with --release".into());
        }
        let options = parse_options_v1(std::env::args().skip(1))?;
        let clock = ControlledBenchmarkClockV1::start_v1();
        let plan_signer = BenchmarkPlanSignerV1::new_v1();
        let plan_resolver = plan_signer.resolver_v1();
        let receipt_keys = ReceiptKeysV1::fixed_v1();
        let grant_resolver = DispatchGrantResolverV1::fixed_v1();
        let dispatch_keys = DispatchKeysV1::fixed_v1();
        let coordinator_receipt_keys = CoordinatorReceiptKeysV1 {
            grant: grant_resolver.clone(),
            receipt: receipt_keys.clone(),
        };

        let mut raw_samples_ns = Vec::with_capacity(MEASURED_OPERATIONS);
        let mut phase_samples = Vec::with_capacity(MEASURED_OPERATIONS);
        let mut committed_receipts = 0_usize;
        let mut coordinator_profile = None;
        let mut adapter_profile = None;
        let mut coordinator_capacities = None;
        let mut adapter_capacity = None;
        let mut filesystem_probe = None;
        let mut benchmark_corpus_hasher = Sha256::new();
        benchmark_corpus_hasher.update(BENCHMARK_CORPUS_DOMAIN_V1);
        for index in 0..TOTAL_OPERATIONS {
            let sequence = u64::try_from(index + 1)?;
            let coordinator_root = TempRootV1::reserve_v1("coordinator")?;
            let adapter_root = TempRootV1::reserve_v1("adapter")?;
            let coordinator_clock = BenchmarkCoordinatorClockV1(clock.clone());
            let (v1_store, root_identity) = initialize_coordinator_v1(
                coordinator_root.path(),
                coordinator_clock.clone(),
                plan_resolver.clone(),
                clock.deadline_after_ms_v1(INITIALIZATION_DEADLINE_MS)?,
            )?;
            let coordinator_database =
                fs::canonicalize(coordinator_root.path())?.join(COORDINATOR_DATABASE_FILENAME);
            let preparation_deadline = clock.deadline_after_ms_v1(PREPARATION_RUN_WINDOW_MS)?;
            let fixture = SampleFixtureV1::try_new_v1(
                sequence,
                &plan_signer,
                clock.clone(),
                preparation_deadline,
            )?;
            append_benchmark_corpus_document_v1(
                &mut benchmark_corpus_hasher,
                sequence,
                &fixture.canonical_plan,
            )?;
            let mut fixtures = vec![fixture];
            provision_scopes_v1(&coordinator_database, &fixtures)?;
            let fixture = fixtures.pop().ok_or("fresh preparation fixture missing")?;
            let committed = fixture
                .case
                .prepare_once_v1(&v1_store, preparation_deadline)
                .map_err(|error| {
                    format!(
                        "controlled preparation {} failed with {}",
                        index + 1,
                        error.code()
                    )
                })?;
            if committed.recovery_provider_calls_v1() != 0 {
                return Err("irreversible preparation called a recovery provider".into());
            }
            drop(v1_store);
            install_exact_v2_overlay_v1(&coordinator_database)?;
            let mut bindings = load_prepared_bindings_v1(&coordinator_database)?;
            if bindings.len() != 1 {
                return Err("fresh coordinator root did not retain exactly one preparation".into());
            }
            let prepared = bindings.pop().ok_or("fresh prepared binding missing")?;
            let coordinator_store = open_coordinator_v2(
                coordinator_root.path(),
                root_identity,
                coordinator_clock,
                plan_resolver.clone(),
                preparation_deadline,
            )?;
            let (adapter_store, adapter_identity, adapter_database) =
                initialize_adapter_v1(adapter_root.path(), prepared.supervisor_epoch)?;
            let signing_profile = receipt_signing_profile_v1(&receipt_keys)?;
            let sampled_monotonic_ms = clock.now_absolute_monotonic_ms_v1()?;
            let sampled_utc_ms = controlled_utc_from_monotonic_v1(sampled_monotonic_ms)?;
            let deadline_monotonic_ms = sampled_monotonic_ms
                .checked_add(DISPATCH_LIFETIME_MS)
                .ok_or("dispatch deadline overflow")?;
            let benchmark_interval = BenchmarkIntervalV1::default();
            let authority = AuthorityFixtureV1 {
                prepared: prepared.clone(),
                sampled_monotonic_ms,
                sampled_utc_ms,
                deadline_monotonic_ms,
                benchmark_interval: benchmark_interval.clone(),
            };
            let adapter_clock = FixedAdapterClockV1 {
                boot_id: prepared.boot_id.clone(),
                generation: 1,
                sampled_utc_ms: sampled_utc_ms + 1,
                sampled_monotonic_ms: sampled_monotonic_ms + 1,
            };
            let adapter_epoch_observer = FreshAdapterEpochObserverV1::open_v1(
                &adapter_database,
                prepared.boot_id.clone(),
                prepared.supervisor_epoch,
                sampled_utc_ms + 1,
                sampled_monotonic_ms + 1,
            )?;
            let transport = AdapterReceiveTransportV1 {
                store: &adapter_store,
                clock: &adapter_clock,
                epoch_observer: &adapter_epoch_observer,
                grant_resolver: grant_resolver.clone(),
            };

            // The fresh real stores, authentic preparation, V2 overlay, preliminary
            // capture, and all per-cycle wiring above are outside the interval. The
            // injected non-authorizing observer starts as the first instruction of
            // fixed-order final-guard acquisition below.
            let retained_dispatch = match dispatch_prepared_once_v1(
                &coordinator_store,
                prepared.lookup_request_v1(deadline_monotonic_ms),
                &authority,
                &SeededDispatchEntropyV1(sequence),
                &dispatch_keys,
                &authority,
            ) {
                DispatchRequestOutcomeV1::Dispatched(retained) => retained,
                DispatchRequestOutcomeV1::Failed(failed) => {
                    return Err(format!(
                        "production dispatch failed at repetition {}: {:?}",
                        index + 1,
                        failed.reason()
                    )
                    .into())
                }
                DispatchRequestOutcomeV1::Denied(denied) => {
                    return Err(format!(
                        "production dispatch was denied at repetition {}: {:?}",
                        index + 1,
                        denied.reason()
                    )
                    .into())
                }
                DispatchRequestOutcomeV1::Ambiguous(ambiguous) => {
                    return Err(format!(
                        "production dispatch was ambiguous at repetition {}: {:?}",
                        index + 1,
                        ambiguous.reason()
                    )
                    .into())
                }
                DispatchRequestOutcomeV1::AlreadyDispatched(_) => {
                    return Err(format!(
                        "production dispatch was unexpectedly prior-exact at repetition {}",
                        index + 1
                    )
                    .into())
                }
            };
            let dispatch_commit_elapsed_ns = benchmark_interval.elapsed_until_v1(Instant::now())?;
            let grant_id = retained_dispatch.grant_id();
            let received = match coordinator_store.handoff_pending_dispatch_v1(
                grant_id,
                deadline_monotonic_ms,
                &transport,
            ) {
                CoordinatorDispatchHandoffOutcomeV1::Acknowledged(received) => received,
                other => {
                    return Err(
                        format!("production handoff was not acknowledged: {other:?}").into(),
                    )
                }
            };
            let handoff_ack_elapsed_ns = benchmark_interval.elapsed_until_v1(Instant::now())?;
            let canonical_receipt = match adapter_store.consume_received_v1(
                received,
                &grant_resolver,
                &adapter_clock,
                &adapter_epoch_observer,
                &RunningAdmissionV1,
                &SeededReceiptEntropyV1(sequence),
                &signing_profile,
                &receipt_keys,
                &receipt_keys,
            ) {
                Ok(AdapterInboxConsumeOutcomeV1::Consumed(receipt)) => {
                    receipt.canonical_receipt().to_vec()
                }
                other => {
                    return Err(format!(
                        "production adapter consume did not retain a consumed receipt: {other:?}"
                    )
                    .into())
                }
            };
            let adapter_consumed_elapsed_ns = benchmark_interval.elapsed_until_v1(Instant::now())?;
            let lookup = CoordinatorReceiptLookupV1::try_new(
                prepared.operation_id.clone(),
                grant_id,
                adapter_identity.to_attested_bytes(),
            )
            .map_err(|_| "coordinator receipt lookup rejected exact bindings")?;
            let receipt_outcome = coordinator_store.commit_execution_receipt_v1(
                lookup,
                &canonical_receipt,
                deadline_monotonic_ms,
                &coordinator_receipt_keys,
            );
            let CoordinatorReceiptCommitOutcomeV1::Committed(evidence) = receipt_outcome else {
                return Err(format!(
                    "exact coordinator receipt did not commit: {receipt_outcome:?}"
                )
                .into());
            };
            if evidence.effective_state() != CoordinatorReceiptEffectiveStateV1::Executing {
                return Err("consumed receipt did not advance to EXECUTING".into());
            }
            let ended = Instant::now();
            let elapsed_ns = benchmark_interval.elapsed_until_v1(ended)?;
            let phase_sample = PhaseSampleV1::try_from_cumulative_v1([
                dispatch_commit_elapsed_ns,
                handoff_ack_elapsed_ns,
                adapter_consumed_elapsed_ns,
                elapsed_ns,
            ])?;
            committed_receipts += 1;
            if index >= WARMUP_OPERATIONS {
                raw_samples_ns.push(elapsed_ns);
                phase_samples.push(phase_sample);
            }
            if coordinator_profile.is_none() {
                coordinator_profile = Some(store_profile_v1(&coordinator_database)?);
                adapter_profile = Some(store_profile_v1(&adapter_database)?);
                coordinator_capacities = Some(coordinator_capacities_v1(&coordinator_database)?);
                adapter_capacity = Some(adapter_capacity_v1(&adapter_database)?);
                filesystem_probe = Some(filesystem_probe_v1(coordinator_root.path())?);
            }
        }
        if raw_samples_ns.len() != MEASURED_OPERATIONS
            || phase_samples.len() != MEASURED_OPERATIONS
            || committed_receipts != TOTAL_OPERATIONS
        {
            return Err("benchmark repetition accounting mismatch".into());
        }

        let coordinator_profile = coordinator_profile.ok_or("coordinator profile missing")?;
        let adapter_profile = adapter_profile.ok_or("adapter profile missing")?;
        let (ordinary_capacity, control_capacity) =
            coordinator_capacities.ok_or("coordinator capacities missing")?;
        let adapter_capacity = adapter_capacity.ok_or("adapter capacity missing")?;
        let filesystem_probe = filesystem_probe.ok_or("filesystem probe missing")?;
        let benchmark_corpus_digest: [u8; 32] = benchmark_corpus_hasher.finalize().into();
        let mut sorted = raw_samples_ns.clone();
        sorted.sort_unstable();
        let characterization = characterize_phases_v1(phase_samples)?;
        let evidence = EvidenceV1 {
            schema: EVIDENCE_SCHEMA_V1,
            acceptance_reference: ACCEPTANCE_ID,
            claim: ClaimV1 {
                evidence_class: "local-diagnostic",
                diagnostic_only: true,
                physical_m4_claim: false,
                acceptance_gate_evaluated: false,
                limitation: "T091 must run this artifact on the controlled physical Mac mini M4 profile before any SC-005 claim",
            },
            environment: EnvironmentV1 {
                hardware: hardware_evidence_v1()?,
                memory_bytes: memory_evidence_v1()?,
                os: os_evidence_v1()?,
                filesystem_type: filesystem_probe.filesystem_type,
                filesystem_assurance: filesystem_probe.assurance,
                architecture: std::env::consts::ARCH,
                rust_toolchain: required_command_output_v1("rustc", &["-vV"] )?,
                cargo_profile: "release",
                cargo_features: enabled_features_v1(),
                available_parallelism: std::thread::available_parallelism()?.get(),
            },
            artifact: ArtifactV1 {
                executable_sha256: sha256_file_v1(&std::env::current_exe()?)?,
                source_sha256: hex_v1(Sha256::digest(include_bytes!(
                    "durable_dispatch_benchmark.rs"
                ))
                .into()),
                cargo_lock_sha256: sha256_file_v1(&cargo_lock_path_v1()?)?,
            },
            schemas: SchemasV1 {
                coordinator_base_v1_sha256: hex_v1(embedded_schema_v1_sha256()),
                coordinator_dispatch_v2_sha256: hex_v1(
                    Sha256::digest(V2_OVERLAY.as_bytes()).into(),
                ),
                adapter_inbox_v1_sha256: hex_v1(
                    Sha256::digest(ADAPTER_INBOX_SCHEMA_V1).into(),
                ),
            },
            corpus: CorpusV1 {
                benchmark_canonical_plans_sha256: hex_v1(benchmark_corpus_digest),
                benchmark_document_count: TOTAL_OPERATIONS,
                benchmark_framing: "domain || sequence_u64_be || canonical_json_length_u64_be || canonical_signed_plan_json_bytes, in sequence order 1..=10500",
                contract_cases_sha256: hex_v1(Sha256::digest(CORPUS_CASES).into()),
                contract_expected_outcomes_sha256: hex_v1(
                    Sha256::digest(CORPUS_EXPECTED).into(),
                ),
                contract_fault_boundaries_sha256: hex_v1(
                    Sha256::digest(CORPUS_FAULT_BOUNDARIES).into(),
                ),
            },
            stores: StoresV1 {
                coordinator: coordinator_profile,
                adapter: adapter_profile,
            },
            workload: WorkloadV1 {
                name: "durable no-effect dispatch through coordinator and independent adapter SQLite stores",
                measured_boundary: "first instruction of fixed-order final-guard acquisition through external validation that commit_execution_receipt_v1 returned Committed with effective state EXECUTING; then Instant captured immediately",
                preparation_boundary: "one authentic unique PLAN-004 preparation and fresh coordinator/adapter roots per repetition, interleaved but completed before that repetition's timer",
                store_lifecycle: "fresh-coordinator-and-adapter-root-per-repetition",
                setup_schedule: "interleaved-per-repetition-outside-measured-interval",
                fixture_corpus: "10,500 unique signed controlled-benchmark plans; one irreversible no-effect operation per fresh store pair",
                warmup_operations: WARMUP_OPERATIONS,
                measured_operations: MEASURED_OPERATIONS,
                total_unique_operations: TOTAL_OPERATIONS,
                concurrency: 1,
                coordinator_ordinary_queue_capacity: ordinary_capacity,
                coordinator_control_queue_capacity: control_capacity,
                adapter_ordinary_queue_capacity: adapter_capacity,
                queue_depth_at_each_new_dispatch: 0,
                retained_preparations_per_coordinator_root: 1,
                retained_grants_per_adapter_root: 1,
                grant_lifetime_ms: DISPATCH_LIFETIME_MS,
                possible_handoff_readback_claim_included: false,
                nominal_wal_full_commit_count: 5,
                acknowledged_attempt_bound_in_receipt_transaction: true,
                production_coordinator_store: true,
                production_adapter_store: true,
                real_adapter_receive_consume: true,
                no_effect_surface: true,
                raw_sample_order: "execution-order-after-warmup",
            },
            characterization,
            results: ResultsV1 {
                duration_unit: "nanoseconds",
                count: raw_samples_ns.len(),
                p50_ns: percentile_v1(&sorted, 50)?,
                p95_ns: percentile_v1(&sorted, 95)?,
                p99_ns: percentile_v1(&sorted, 99)?,
                max_ns: *sorted.last().ok_or("no measured samples")?,
                raw_samples_ns,
                reference_p95_limit_ns: P95_REFERENCE_LIMIT_NS,
                reference_p99_limit_ns: P99_REFERENCE_LIMIT_NS,
                reference_limits_are_acceptance_verdict: false,
                committed_executing_receipts: committed_receipts,
            },
        };
        write_new_json_v1(&options.output, &evidence)?;
        Ok(())
    }

    impl SampleFixtureV1 {
        fn try_new_v1(
            sequence: u64,
            signer: &BenchmarkPlanSignerV1,
            clock: ControlledBenchmarkClockV1,
            deadline_monotonic_ms: u64,
        ) -> Result<Self, Box<dyn Error>> {
            let signed = sign_plan_v1(plan_input_v1(sequence)?, signer)?;
            let canonical = signed.to_canonical_json()?;
            let authentic = decode_and_verify_plan(&canonical, &signer.resolver_v1())?;
            let case =
                build_controlled_benchmark_case_v1(authentic, clock, deadline_monotonic_ms, 1)?;
            Ok(Self {
                case,
                canonical_plan: canonical,
            })
        }
    }

    fn plan_input_v1(sequence: u64) -> Result<PlanInputV1, Box<dyn Error>> {
        let mut nonce = [0xa4_u8; 16];
        nonce[8..].copy_from_slice(&sequence.to_be_bytes());
        Ok(PlanInputV1 {
            operation_id: format!("operation:benchmark-{sequence:016x}"),
            task_id: format!("task:benchmark-{sequence:016x}"),
            workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1.to_owned(),
            boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1.to_owned(),
            task_lease_digest: plan_digest_v1(b"task-lease", sequence),
            request_source_kind: RequestSourceKindV1::HumanRequestGrant,
            request_source_digest: plan_digest_v1(b"request-source", sequence),
            catalog_version: CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1.to_owned(),
            policy_version: CONTROLLED_BENCHMARK_POLICY_VERSION_V1.to_owned(),
            risk_level: RiskLevelV1::L2,
            target: ResourceRefV1::new(
                "vault-controlled-benchmark",
                ["Public", "Controlled", "Target.md"],
            )?,
            precondition: FilePreconditionInputV1 {
                volume_id: "volume:controlled-benchmark".to_owned(),
                file_id: format!("file:benchmark-{sequence:016x}"),
                content_sha256: plan_digest_v1(b"precondition", sequence),
                byte_length: 7,
            },
            replacement_bytes: format!("after-{sequence:016x}\n").into_bytes(),
            replacement_media_type: "text/markdown".to_owned(),
            recovery: RecoveryInputV1 {
                class: RecoveryClassV1::Irreversible,
                atomicity: AtomicityV1::NonAtomic,
                reserved_bytes: 0,
            },
            capability_report_digest: plan_digest_v1(b"capability-report", sequence),
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

    fn initialize_coordinator_v1(
        root: &Path,
        clock: BenchmarkCoordinatorClockV1,
        resolver: BenchmarkPlanResolverV1,
        deadline_monotonic_ms: u64,
    ) -> Result<(BenchmarkStoreV1, CoordinatorRootIdentityEvidenceV1), Box<dyn Error>> {
        fs::create_dir(root)?;
        let config =
            CoordinatorStoreConfigV1::try_new_empty_attested(root.to_path_buf(), BUSY_WAIT_MS)?;
        let store = SqliteCoordinatorStoreV1::open_or_create(
            config,
            clock,
            resolver,
            deadline_monotonic_ms,
        )?;
        let identity = store.root_identity_evidence();
        Ok((store, identity))
    }

    fn open_coordinator_v2(
        root: &Path,
        root_identity: CoordinatorRootIdentityEvidenceV1,
        clock: BenchmarkCoordinatorClockV1,
        resolver: BenchmarkPlanResolverV1,
        deadline_monotonic_ms: u64,
    ) -> Result<BenchmarkStoreV2, Box<dyn Error>> {
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            root.to_path_buf(),
            root_identity,
            BUSY_WAIT_MS,
        )?;
        Ok(SqliteCoordinatorStoreV2::open_existing(
            config,
            clock,
            resolver,
            deadline_monotonic_ms,
        )?)
    }

    fn open_write_connection_v1(database: &Path) -> Result<Connection, Box<dyn Error>> {
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
        Ok(connection)
    }

    fn provision_scopes_v1(
        database: &Path,
        fixtures: &[SampleFixtureV1],
    ) -> Result<(), Box<dyn Error>> {
        let mut connection = open_write_connection_v1(database)?;
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
        let generation = i64::try_from(fixtures.len())?;
        if transaction.execute(
            "UPDATE coordinator_store_meta
             SET store_generation=?1, budget_generation=?1
             WHERE singleton=1 AND root_lifecycle_state='ACTIVE'
               AND store_generation=0 AND budget_generation=0",
            [generation],
        )? != 1
        {
            return Err("benchmark scope metadata preprovision failed".into());
        }
        transaction.commit()?;
        Ok(())
    }

    fn install_exact_v2_overlay_v1(database: &Path) -> Result<(), Box<dyn Error>> {
        let connection = Connection::open(database)?;
        let root_identity: Vec<u8> = connection.query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch(V2_OVERLAY)?;
        connection.execute(
            "INSERT INTO dispatch_store_meta (
                singleton, extension_format_version, dispatch_store_generation,
                dispatch_generation, delivery_generation, receipt_generation,
                reconciliation_generation, event_generation, migration_generation,
                ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state,
                restore_index_digest, restore_state_generation
             ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, 'ACTIVE', NULL, 0)",
            [],
        )?;
        connection.execute(
            "INSERT INTO coordinator_v2_migrations (
                migration_attempt_id, source_schema_digest, source_root_identity,
                source_summary_digest, verified_backup_digest, overlay_schema_digest,
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms,
                tool_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000,
                       'helixos-t084-local-diagnostic-v1')",
            params![
                [0x84_u8; 32].as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                [0x85_u8; 32].as_slice(),
                [0x86_u8; 32].as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )?;
        Ok(())
    }

    fn load_prepared_bindings_v1(
        database: &Path,
    ) -> Result<Vec<PreparedDispatchBindingsV1>, Box<dyn Error>> {
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let mut statement = connection.prepare(
            "SELECT operation.operation_id, operation.attempt_id, operation.plan_id,
                    operation.state_generation, operation.task_id, operation.workload_id,
                    operation.boot_id, operation.instance_epoch, operation.fencing_epoch,
                    operation.reservation_id, reservation.task_lease_digest,
                    operation.recovery_mode
             FROM prepared_operations AS operation
             JOIN budget_reservations AS reservation
               ON reservation.reservation_id = operation.reservation_id
              AND reservation.operation_id = operation.operation_id
              AND reservation.attempt_id = operation.attempt_id
              AND reservation.plan_id = operation.plan_id
              AND reservation.reservation_state = 'HELD'
              AND reservation.released_generation IS NULL
             WHERE operation.operation_state = 'PREPARING'
             ORDER BY operation.operation_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, String>(11)?,
            ))
        })?;
        let mut bindings = Vec::with_capacity(TOTAL_OPERATIONS);
        for row in rows {
            let row = row?;
            bindings.push(PreparedDispatchBindingsV1 {
                operation_id: row.0,
                preparation_attempt_id: exact_array_v1(row.1)?,
                plan_id: exact_array_v1(row.2)?,
                preparation_transition_generation: u64::try_from(row.3)?,
                task_id: row.4,
                workload_id: row.5,
                boot_id: row.6,
                instance_epoch: u64::try_from(row.7)?,
                supervisor_epoch: u64::try_from(row.8)?,
                reservation_id: row.9,
                task_lease_digest: exact_array_v1(row.10)?,
                recovery_mode: match row.11.as_str() {
                    "COMPENSATION" => RecoveryModeV1::Compensation,
                    "IRREVERSIBLE" => RecoveryModeV1::Irreversible,
                    _ => return Err("unsupported prepared recovery mode".into()),
                },
            });
        }
        Ok(bindings)
    }

    fn initialize_adapter_v1(
        root: &Path,
        supervisor_epoch: u64,
    ) -> Result<
        (
            SqliteDispatchInboxStoreV1,
            AdapterInboxRootIdentityEvidenceV1,
            PathBuf,
        ),
        Box<dyn Error>,
    > {
        fs::create_dir(root)?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"HELIXOS\0T084-ADAPTER-ROOT\0V1\0");
        preimage.extend_from_slice(&std::process::id().to_be_bytes());
        preimage.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_be_bytes(),
        );
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(
            Sha256::digest(&preimage).into(),
        );
        let config = AdapterInboxStoreConfigV1::try_new_empty_attested(
            root.to_path_buf(),
            identity,
            BUSY_WAIT_MS,
        )?;
        let initial = AdapterInboxInitializationV1::try_new(
            supervisor_epoch,
            1,
            RECEIPT_SIGNER_PROFILE_DIGEST,
        )?;
        let store = SqliteDispatchInboxStoreV1::initialize_empty_v1(
            config,
            initial,
            adapter_profile_v1()?,
        )?;
        let database = fs::canonicalize(root)?.join(ADAPTER_DATABASE_FILENAME);
        Ok((store, identity, database))
    }

    fn adapter_profile_v1() -> Result<AdapterInboxProfileV1, Box<dyn Error>> {
        Ok(AdapterInboxProfileV1::try_new(
            DESTINATION_ADAPTER_ID,
            1,
            Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
        )?)
    }

    fn receipt_signing_profile_v1(
        keys: &ReceiptKeysV1,
    ) -> Result<AdapterReceiptSigningProfileV1, Box<dyn Error>> {
        Ok(AdapterReceiptSigningProfileV1::try_new(
            RECEIPT_SIGNER_KEY_ID,
            Sha256Digest::digest(&keys.signing_key.verifying_key().to_bytes()),
            Sha256Digest::from_bytes(RECEIPT_SIGNER_PROFILE_DIGEST),
        )?)
    }

    fn parse_options_v1<I>(arguments: I) -> Result<OptionsV1, Box<dyn Error>>
    where
        I: IntoIterator<Item = String>,
    {
        let mut output = None;
        let mut warmups = None;
        let mut samples = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{argument} requires a value"))?;
            match argument.as_str() {
                "--output" => {
                    if output.replace(PathBuf::from(value)).is_some() {
                        return Err("--output may appear only once".into());
                    }
                }
                "--warmups" => {
                    if warmups.replace(value.parse::<usize>()?).is_some() {
                        return Err("--warmups may appear only once".into());
                    }
                }
                "--samples" => {
                    if samples.replace(value.parse::<usize>()?).is_some() {
                        return Err("--samples may appear only once".into());
                    }
                }
                _ => return Err(format!("unknown benchmark argument: {argument}").into()),
            }
        }
        let warmups = warmups.ok_or("--warmups is required")?;
        let samples = samples.ok_or("--samples is required")?;
        if warmups != WARMUP_OPERATIONS || samples != MEASURED_OPERATIONS {
            return Err("T084 requires exactly --warmups 500 --samples 10000".into());
        }
        Ok(OptionsV1 {
            output: output.ok_or("--output is required")?,
            warmups,
            samples,
        })
    }

    fn write_new_json_v1<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
        let parent = path
            .parent()
            .ok_or("--output requires a parent directory")?;
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        Ok(())
    }

    fn store_profile_v1(database: &Path) -> Result<StoreProfileV1, Box<dyn Error>> {
        let connection = Connection::open(database)?;
        connection.busy_timeout(Duration::from_millis(BUSY_WAIT_MS))?;
        connection.execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=0;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA cell_size_check=ON;
             PRAGMA recursive_triggers=ON;",
        )?;
        let sqlite_version: String =
            connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
        let sqlite_source_id: String =
            connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
        let linked_source_id = rusqlite::ffi::SQLITE_SOURCE_ID.to_str()?;
        if sqlite_version.is_empty()
            || sqlite_source_id.is_empty()
            || sqlite_version != rusqlite::version()
            || sqlite_source_id != linked_source_id
        {
            return Err("SQLite runtime identity does not match the linked exact source".into());
        }
        Ok(StoreProfileV1 {
            application_id: pragma_i64_v1(&connection, "application_id")?,
            schema_version: pragma_i64_v1(&connection, "user_version")?,
            sqlite_version,
            sqlite_source_id,
            journal_mode: connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
            synchronous: pragma_i64_v1(&connection, "synchronous")?,
            wal_autocheckpoint_pages: pragma_i64_v1(&connection, "wal_autocheckpoint")?,
            foreign_keys: pragma_i64_v1(&connection, "foreign_keys")?,
            trusted_schema: pragma_i64_v1(&connection, "trusted_schema")?,
            cell_size_check: pragma_i64_v1(&connection, "cell_size_check")?,
            recursive_triggers: pragma_i64_v1(&connection, "recursive_triggers")?,
            busy_wait_ms: BUSY_WAIT_MS,
        })
    }

    fn pragma_i64_v1(connection: &Connection, name: &str) -> Result<i64, Box<dyn Error>> {
        let allowed = [
            "application_id",
            "user_version",
            "synchronous",
            "wal_autocheckpoint",
            "foreign_keys",
            "trusted_schema",
            "cell_size_check",
            "recursive_triggers",
        ];
        if !allowed.contains(&name) {
            return Err("unsupported benchmark pragma".into());
        }
        Ok(connection.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))?)
    }

    fn coordinator_capacities_v1(database: &Path) -> Result<(i64, i64), Box<dyn Error>> {
        let connection = Connection::open(database)?;
        Ok(connection.query_row(
            "SELECT ordinary_queue_capacity, control_queue_capacity
             FROM dispatch_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    fn adapter_capacity_v1(database: &Path) -> Result<i64, Box<dyn Error>> {
        let connection = Connection::open(database)?;
        Ok(connection.query_row(
            "SELECT ordinary_queue_capacity FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?)
    }

    fn characterize_phases_v1(
        samples: Vec<PhaseSampleV1>,
    ) -> Result<CharacterizationV1, Box<dyn Error>> {
        if samples.is_empty()
            || !samples
                .iter()
                .copied()
                .all(PhaseSampleV1::partition_is_exact_v1)
        {
            return Err("phase characterization is empty or inexact".into());
        }
        let summaries = PhaseSummariesV1 {
            final_guard_to_dispatch_commit: summarize_phase_v1(&samples, |sample| {
                sample.final_guard_to_dispatch_commit_ns
            })?,
            dispatch_commit_to_handoff_ack: summarize_phase_v1(&samples, |sample| {
                sample.dispatch_commit_to_handoff_ack_ns
            })?,
            handoff_ack_to_adapter_consumed: summarize_phase_v1(&samples, |sample| {
                sample.handoff_ack_to_adapter_consumed_ns
            })?,
            adapter_consumed_to_coordinator_receipt_commit: summarize_phase_v1(
                &samples,
                |sample| sample.adapter_consumed_to_coordinator_receipt_commit_ns,
            )?,
        };
        Ok(CharacterizationV1 {
            clock: "std::time::Instant monotonic timeline shared with the acceptance interval",
            boundary_order: [
                "final-guard-entry",
                "dispatch-commit-returned",
                "handoff-acknowledged",
                "adapter-consumed-receipt-returned",
                "coordinator-receipt-commit-returned",
            ],
            sample_count: samples.len(),
            every_sample_exactly_partitions_total: true,
            summaries,
            raw_samples: samples,
        })
    }

    fn summarize_phase_v1<F>(
        samples: &[PhaseSampleV1],
        select: F,
    ) -> Result<PhaseSummaryV1, Box<dyn Error>>
    where
        F: Fn(PhaseSampleV1) -> u64,
    {
        let mut values = samples.iter().copied().map(select).collect::<Vec<_>>();
        values.sort_unstable();
        Ok(PhaseSummaryV1 {
            p50_ns: percentile_v1(&values, 50)?,
            p95_ns: percentile_v1(&values, 95)?,
            p99_ns: percentile_v1(&values, 99)?,
            max_ns: *values.last().ok_or("phase characterization is empty")?,
        })
    }

    fn percentile_v1(sorted: &[u64], percentile: usize) -> Result<u64, Box<dyn Error>> {
        if sorted.is_empty() || !(1..=100).contains(&percentile) {
            return Err("invalid percentile input".into());
        }
        let rank = percentile
            .checked_mul(sorted.len())
            .and_then(|value| value.checked_add(99))
            .ok_or("percentile rank overflow")?
            / 100;
        Ok(sorted[rank.saturating_sub(1)])
    }

    fn controlled_utc_from_monotonic_v1(monotonic_ms: u64) -> Result<u64, Box<dyn Error>> {
        let elapsed = monotonic_ms
            .checked_sub(CONTROLLED_BASE_MONOTONIC_MS)
            .ok_or("controlled monotonic clock regressed")?;
        Ok(CONTROLLED_BASE_UTC_MS
            .checked_add(elapsed)
            .ok_or("controlled UTC clock overflow")?)
    }

    fn plan_digest_v1(domain: &[u8], sequence: u64) -> PlanSha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0T084-PLAN-FIXTURE\0V1\0");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update(sequence.to_be_bytes());
        PlanSha256Digest::from_bytes(hasher.finalize().into())
    }

    fn dispatch_entropy_domain_tag_v1(domain: DispatchEntropyDomainV1) -> u8 {
        match domain {
            DispatchEntropyDomainV1::AttemptIdentity => 1,
            DispatchEntropyDomainV1::GrantIdentity => 2,
            DispatchEntropyDomainV1::OneShotNonce => 3,
            DispatchEntropyDomainV1::TraceIdentity => 4,
        }
    }

    fn exact_array_v1(bytes: Vec<u8>) -> Result<[u8; 32], Box<dyn Error>> {
        bytes
            .try_into()
            .map_err(|_| "expected an exact 32-byte durable binding".into())
    }

    fn identifier_v1(value: &str) -> Identifier {
        Identifier::new(value).expect("T084 identifier is valid")
    }

    fn generation_v1(value: u64) -> Generation {
        Generation::new(value).expect("T084 generation is valid")
    }

    fn safe_v1(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("T084 safe integer is valid")
    }

    fn digest_byte_v1(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn dispatch_key_fingerprint_v1() -> Sha256Digest {
        Sha256Digest::digest(&DispatchGrantResolverV1::fixed_v1().verifying_key)
    }

    fn enabled_features_v1() -> Vec<&'static str> {
        let mut features = vec!["controlled-benchmark"];
        if cfg!(feature = "test-fault-injection") {
            features.push("test-fault-injection");
        }
        features
    }

    #[cfg(target_os = "macos")]
    fn hardware_evidence_v1() -> Result<String, Box<dyn Error>> {
        let model = required_command_output_v1("sysctl", &["-n", "hw.model"])?;
        let processor = required_command_output_v1("sysctl", &["-n", "machdep.cpu.brand_string"])?;
        Ok(format!("{processor}; model {model}"))
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn hardware_evidence_v1() -> Result<String, Box<dyn Error>> {
        required_command_output_v1("uname", &["-m"])
    }

    #[cfg(target_os = "windows")]
    fn hardware_evidence_v1() -> Result<String, Box<dyn Error>> {
        required_command_output_v1(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
            ],
        )
    }

    #[cfg(target_os = "macos")]
    fn memory_evidence_v1() -> Result<String, Box<dyn Error>> {
        let bytes = required_command_output_v1("sysctl", &["-n", "hw.memsize"])?;
        let parsed = bytes.parse::<u64>()?;
        if parsed == 0 {
            return Err("physical-memory probe returned zero".into());
        }
        Ok(bytes)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn memory_evidence_v1() -> Result<String, Box<dyn Error>> {
        let pages = required_command_output_v1("getconf", &["_PHYS_PAGES"])?.parse::<u64>()?;
        let page_bytes = required_command_output_v1("getconf", &["PAGE_SIZE"])?.parse::<u64>()?;
        Ok(pages
            .checked_mul(page_bytes)
            .filter(|bytes| *bytes > 0)
            .ok_or("physical-memory probe overflowed")?
            .to_string())
    }

    #[cfg(target_os = "windows")]
    fn memory_evidence_v1() -> Result<String, Box<dyn Error>> {
        required_command_output_v1(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ],
        )
    }

    #[cfg(target_os = "macos")]
    fn os_evidence_v1() -> Result<String, Box<dyn Error>> {
        let version = required_command_output_v1("sw_vers", &["-productVersion"])?;
        let build = required_command_output_v1("sw_vers", &["-buildVersion"])?;
        Ok(format!("macOS {version} ({build})"))
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn os_evidence_v1() -> Result<String, Box<dyn Error>> {
        let system = required_command_output_v1("uname", &["-s"])?;
        let release = required_command_output_v1("uname", &["-r"])?;
        let version = required_command_output_v1("uname", &["-v"])?;
        Ok(format!("{system} {release}; {version}"))
    }

    #[cfg(target_os = "windows")]
    fn os_evidence_v1() -> Result<String, Box<dyn Error>> {
        required_command_output_v1("cmd", &["/C", "ver"])
    }

    #[cfg(target_os = "macos")]
    fn filesystem_probe_v1(path: &Path) -> Result<FilesystemProbeV1, Box<dyn Error>> {
        let canonical = fs::canonicalize(path)?;
        let canonical = canonical
            .to_str()
            .ok_or("benchmark root path is not UTF-8")?;
        let df = required_command_output_v1("df", &["-P", canonical])?;
        let device = df
            .lines()
            .nth(1)
            .and_then(|line| line.split_whitespace().next())
            .filter(|value| !value.is_empty())
            .ok_or("filesystem device probe was unreadable")?;
        let disk = required_command_output_v1("diskutil", &["info", device])?;
        let filesystem_type = required_labeled_value_v1(&disk, "File System Personality")?;
        let location = required_labeled_value_v1(&disk, "Device Location")?;
        let solid_state = required_labeled_value_v1(&disk, "Solid State")?;
        let file_vault = required_labeled_value_v1(&disk, "FileVault")?;
        let smart_status = required_labeled_value_v1(&disk, "SMART Status")?;
        Ok(FilesystemProbeV1 {
            filesystem_type,
            assurance: format!(
                "device_location={location}; solid_state={solid_state}; filevault={file_vault}; smart_status={smart_status}; diagnostic-only-no-power-loss-claim"
            ),
        })
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn filesystem_probe_v1(path: &Path) -> Result<FilesystemProbeV1, Box<dyn Error>> {
        let canonical = fs::canonicalize(path)?;
        let canonical = canonical
            .to_str()
            .ok_or("benchmark root path is not UTF-8")?;
        Ok(FilesystemProbeV1 {
            filesystem_type: required_command_output_v1("stat", &["-f", "-c", "%T", canonical])?,
            assurance: "filesystem-type-observed; sqlite-wal-synchronous-full; diagnostic-only-no-power-loss-claim".to_owned(),
        })
    }

    #[cfg(target_os = "windows")]
    fn filesystem_probe_v1(_path: &Path) -> Result<FilesystemProbeV1, Box<dyn Error>> {
        Err("T084 filesystem assurance probe is not implemented on Windows".into())
    }

    fn required_labeled_value_v1(output: &str, label: &str) -> Result<String, Box<dyn Error>> {
        output
            .lines()
            .find_map(|line| {
                let (candidate, value) = line.split_once(':')?;
                (candidate.trim() == label)
                    .then(|| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
            })
            .ok_or_else(|| format!("required filesystem probe field {label} is absent").into())
    }

    fn required_command_output_v1(
        program: &str,
        arguments: &[&str],
    ) -> Result<String, Box<dyn Error>> {
        let output = Command::new(program).args(arguments).output()?;
        if !output.status.success() {
            return Err(format!("required metadata probe {program} failed").into());
        }
        let value = String::from_utf8(output.stdout)?.trim().to_owned();
        if value.is_empty() || value.contains('\0') {
            return Err(
                format!("required metadata probe {program} returned no usable value").into(),
            );
        }
        Ok(value)
    }

    fn cargo_lock_path_v1() -> Result<PathBuf, Box<dyn Error>> {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let kernel = manifest
            .parent()
            .ok_or("crate manifest has no workspace parent")?;
        let lock = kernel.join("Cargo.lock");
        if !lock.is_file() {
            return Err("workspace Cargo.lock is absent".into());
        }
        Ok(lock)
    }

    fn append_benchmark_corpus_document_v1(
        hasher: &mut Sha256,
        sequence: u64,
        canonical_plan: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        if canonical_plan.is_empty() {
            return Err("benchmark corpus contains an empty canonical plan".into());
        }
        hasher.update(sequence.to_be_bytes());
        hasher.update(u64::try_from(canonical_plan.len())?.to_be_bytes());
        hasher.update(canonical_plan);
        Ok(())
    }

    fn sha256_file_v1(path: &Path) -> Result<String, Box<dyn Error>> {
        Ok(hex_v1(Sha256::digest(fs::read(path)?).into()))
    }

    fn hex_v1(bytes: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[cfg(test)]
    mod tests {
        use super::{
            parse_options_v1, percentile_v1, BenchmarkIntervalV1, FreshAdapterEpochObserverV1,
            PhaseSampleV1, SupervisorEpochObservationV1, SupervisorEpochObserverV1, TempRootV1,
            ADAPTER_INBOX_SCHEMA_V1, EXPECTED_ADAPTER_INBOX_SCHEMA_V1_SHA256, MEASURED_OPERATIONS,
            WARMUP_OPERATIONS,
        };
        use sha2::{Digest as _, Sha256};
        use std::fs;
        use std::time::Instant;

        #[test]
        fn options_accept_only_the_exact_t084_repetitions() {
            let exact = parse_options_v1([
                "--warmups".to_owned(),
                WARMUP_OPERATIONS.to_string(),
                "--samples".to_owned(),
                MEASURED_OPERATIONS.to_string(),
                "--output".to_owned(),
                "diagnostic.json".to_owned(),
            ])
            .expect("exact T084 options validate");
            assert_eq!(exact.warmups, 500);
            assert_eq!(exact.samples, 10_000);

            assert!(parse_options_v1([
                "--warmups".to_owned(),
                "499".to_owned(),
                "--samples".to_owned(),
                "10000".to_owned(),
                "--output".to_owned(),
                "diagnostic.json".to_owned(),
            ])
            .is_err());
            assert!(parse_options_v1([
                "--warmups".to_owned(),
                "500".to_owned(),
                "--samples".to_owned(),
                "9999".to_owned(),
                "--output".to_owned(),
                "diagnostic.json".to_owned(),
            ])
            .is_err());
        }

        #[test]
        fn percentiles_use_exact_nearest_rank_indices() {
            let sorted = (1_u64..=10_000).collect::<Vec<_>>();
            assert_eq!(percentile_v1(&sorted, 50).unwrap(), 5_000);
            assert_eq!(percentile_v1(&sorted, 95).unwrap(), 9_500);
            assert_eq!(percentile_v1(&sorted, 99).unwrap(), 9_900);
        }

        #[test]
        fn adapter_schema_digest_matches_the_pinned_production_digest() {
            let actual: [u8; 32] = Sha256::digest(ADAPTER_INBOX_SCHEMA_V1).into();
            assert_eq!(actual, EXPECTED_ADAPTER_INBOX_SCHEMA_V1_SHA256);
        }

        #[test]
        fn one_read_only_epoch_observer_refreshes_its_wal_snapshot_after_commit() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<FreshAdapterEpochObserverV1>();

            let root =
                TempRootV1::reserve_v1("epoch-observer-test").expect("observer test root reserves");
            fs::create_dir(root.path()).expect("observer test root creates");
            let database = fs::canonicalize(root.path())
                .expect("observer test root canonicalizes")
                .join("epoch-observer.sqlite3");
            let writer = rusqlite::Connection::open(&database).expect("writer opens");
            writer
                .execute_batch(
                    "PRAGMA journal_mode = WAL; \
                     PRAGMA synchronous = FULL; \
                     CREATE TABLE adapter_store_meta ( \
                         singleton INTEGER PRIMARY KEY, \
                         epoch_observer_generation INTEGER NOT NULL); \
                     INSERT INTO adapter_store_meta \
                         (singleton, epoch_observer_generation) VALUES (1, 1);",
                )
                .expect("observer fixture initializes");
            let observer = FreshAdapterEpochObserverV1::open_v1(
                &database,
                "boot:observer-test".to_owned(),
                9,
                101,
                102,
            )
            .expect("one persistent read-only observer opens");
            let generation = |observation| match observation {
                SupervisorEpochObservationV1::Current(observation) => {
                    observation.observer_generation()
                }
                other => panic!("observer did not return current authority: {other:?}"),
            };

            assert_eq!(generation(observer.observe_supervisor_epoch_v1()), 2);
            assert!(
                observer
                    .connection
                    .lock()
                    .expect("observer mutex remains healthy")
                    .is_autocommit(),
                "one observation must not retain a read transaction"
            );
            writer
                .execute_batch(
                    "BEGIN IMMEDIATE; \
                     UPDATE adapter_store_meta SET epoch_observer_generation = 7 \
                     WHERE singleton = 1;",
                )
                .expect("writer stages a generation without commit");
            assert_eq!(
                generation(observer.observe_supervisor_epoch_v1()),
                2,
                "independent observer must not see uncommitted adapter state"
            );
            writer.execute_batch("COMMIT;").expect("writer commits");
            assert_eq!(
                generation(observer.observe_supervisor_epoch_v1()),
                8,
                "the same handle must begin a fresh WAL snapshot after commit"
            );
            let observer_connection = observer
                .connection
                .lock()
                .expect("observer mutex remains healthy");
            assert!(observer_connection.is_autocommit());
            assert!(
                observer_connection
                    .execute(
                        "UPDATE adapter_store_meta SET epoch_observer_generation = 99 \
                         WHERE singleton = 1",
                        [],
                    )
                    .is_err(),
                "observer handle must remain read-only"
            );
        }

        #[test]
        fn measured_interval_requires_exactly_one_final_guard_entry() {
            let interval = BenchmarkIntervalV1::default();
            assert!(interval.elapsed_until_v1(Instant::now()).is_err());
            assert!(interval.start_at_final_guard_entry_v1().is_ok());
            assert!(interval.start_at_final_guard_entry_v1().is_err());
            assert!(interval.elapsed_until_v1(Instant::now()).is_ok());
        }

        #[test]
        fn characterization_is_an_exact_ordered_partition_of_the_acceptance_interval() {
            let sample = PhaseSampleV1::try_from_cumulative_v1([11, 29, 73, 101])
                .expect("ordered cumulative boundaries characterize");
            assert_eq!(sample.final_guard_to_dispatch_commit_ns, 11);
            assert_eq!(sample.dispatch_commit_to_handoff_ack_ns, 18);
            assert_eq!(sample.handoff_ack_to_adapter_consumed_ns, 44);
            assert_eq!(sample.adapter_consumed_to_coordinator_receipt_commit_ns, 28);
            assert_eq!(sample.total_ns, 101);
            assert!(sample.partition_is_exact_v1());
            assert!(PhaseSampleV1::try_from_cumulative_v1([11, 10, 73, 101]).is_err());
        }
    }
}
