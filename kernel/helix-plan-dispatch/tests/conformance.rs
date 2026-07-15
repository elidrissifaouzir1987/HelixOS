//! One unchanged, host-independent PLAN-005 no-effect conformance corpus.

#![forbid(unsafe_code)]

use helix_dispatch_contracts::{
    ContractError, Generation, GrantSigner, Identifier, RecoveryModeV1, ResourceRefV1, SafeU64,
    Sha256Digest,
};
use helix_plan_dispatch::{
    dispatch_prepared_once_v1, receive_and_consume_exact_grant_v1, recover_lost_acknowledgement_v1,
    run_automatic_readback_once_v1, DispatchAuthorityCaptureOutcomeV1,
    DispatchAuthorityCapturePhaseV1, DispatchAuthorityProviderV1, DispatchAuthorityViewInputV1,
    DispatchAuthorityViewV1, DispatchAutomaticHandoffClassificationV1,
    DispatchAutomaticReadbackGateV1, DispatchAutomaticReadbackOutcomeV1,
    DispatchAutomaticReadbackScheduleV1, DispatchCapacityVectorV1, DispatchCommitCandidateV1,
    DispatchCommitEvidenceV1, DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1,
    DispatchCommitResolutionV1, DispatchCoordinatorStoreV1, DispatchEffectDescriptorInputV1,
    DispatchEffectDescriptorV1, DispatchEntropyDomainV1, DispatchEntropyErrorV1,
    DispatchEntropySourceV1, DispatchGuardAcquisitionV1, DispatchGuardClassV1,
    DispatchGuardOrderErrorV1, DispatchGuardProviderV1, DispatchGuardSetV1,
    DispatchGuardValidationV1, DispatchInboxAdapterOutcomeV1, DispatchInboxConsumeOutcomeV1,
    DispatchInboxConsumerV1, DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1,
    DispatchInboxReceiveOutcomeV1, DispatchInboxV1, DispatchLookupRequestInputV1,
    DispatchLookupRequestV1, DispatchLostAcknowledgementRecoveryV1, DispatchReadbackWaitOutcomeV1,
    DispatchReconciliationReasonV1, DispatchReloadOutcomeV1, DispatchReloadedCandidateV1,
    DispatchRequestOutcomeV1, DispatchRetainedProjectionV1, DispatchStoreCommitClassificationV1,
    DispatchStoreReadbackOutcomeV1, DispatchTimeCaptureV1, DispatchUnknownReasonV1,
    DISPATCH_AUTHORITY_VIEW_VERSION_V1,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::{DispatchFaultProbeV1, FaultInjectionDecisionV1, FaultInjectionModeV1};

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const EXPECTED_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json");
const END_TO_END_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/end-to-end-cases.json");
const FAULT_FIXTURE_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/fault-boundaries.json");
const FAULT_REGISTRY_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");

const CASES_RAW_SHA256: &str = "70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a";
const EXPECTED_RAW_SHA256: &str =
    "8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4";
const CASES_JCS_SHA256: &str = "5aa36b610d3bc9a8cdf0603a947bb6a97d7c83c77c8d8c30e169734f9e3ad42b";
const EXPECTED_JCS_SHA256: &str =
    "7b9283a4f315319f6cc187c29fc01733c530ae50e7ff4002250e5cbe5161bf78";
const END_TO_END_SHA256: &str = "d075223c2bbf58f0e434796f5aa44058c73f826de7ecec895330f690377bb44c";
const FAULT_FIXTURE_RAW_SHA256: &str =
    "041c2eca7dfdc5b3c3a0a7b5a3d1399c26133f9fe63e8a26e23c9bc9bab7ef3b";
const FAULT_FIXTURE_JCS_SHA256: &str =
    "8452a6e2e92d0ed8c032762f50d441e53167c18990fa7f6d2fc505680aa452dc";
const FAULT_REGISTRY_RAW_SHA256: &str =
    "afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26";
const FAULT_REGISTRY_JCS_SHA256: &str =
    "4f18a6dcc2c5496af07b3947189225635e958c7b9fb66ea279e21f322ac58c2b";

const SCENARIO_MEMBER_KEYS: [&str; 15] = [
    "activation_authorized",
    "automatic_redelivery_count",
    "control_state",
    "durable_evidence",
    "durable_projection",
    "effect_authorized",
    "evidence_scope",
    "execution",
    "host_effect_count",
    "id",
    "ordinal",
    "outcome",
    "replacement_grant_count",
    "state",
    "subsystem_only",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScenarioV1 {
    ordinal: u64,
    id: &'static str,
    execution: &'static str,
    durable_projection: &'static str,
    outcome: &'static str,
    state: &'static str,
    control_state: &'static str,
}

const SCENARIOS: [ScenarioV1; 6] = [
    ScenarioV1 {
        ordinal: 1,
        id: "migration",
        execution: "external-store-evidence",
        durable_projection: "coordinator-v2-migration-receipt",
        outcome: "migrated",
        state: "ACTIVE",
        control_state: "RUNNING",
    },
    ScenarioV1 {
        ordinal: 2,
        id: "dispatch",
        execution: "portable-production-path",
        durable_projection: "coordinator-dispatch-commit",
        outcome: "dispatched",
        state: "DISPATCHING",
        control_state: "RUNNING",
    },
    ScenarioV1 {
        ordinal: 3,
        id: "consume",
        execution: "portable-production-path",
        durable_projection: "adapter-consumed-receipt",
        outcome: "consumed",
        state: "EXECUTING",
        control_state: "RUNNING",
    },
    ScenarioV1 {
        ordinal: 4,
        id: "lost-ack",
        execution: "portable-production-path",
        durable_projection: "adapter-retained-receipt",
        outcome: "receipt-recovered",
        state: "EXECUTING",
        control_state: "RUNNING",
    },
    ScenarioV1 {
        ordinal: 5,
        id: "unknown",
        execution: "portable-production-path",
        durable_projection: "coordinator-reconciliation-custody",
        outcome: "reconciliation-required",
        state: "RECONCILIATION_REQUIRED",
        control_state: "RUNNING",
    },
    ScenarioV1 {
        ordinal: 6,
        id: "clean-restore",
        execution: "external-store-evidence",
        durable_projection: "cross-store-restore-pending",
        outcome: "restored-pending",
        state: "RESTORE_PENDING",
        control_state: "PAUSED",
    },
];

#[test]
fn frozen_contract_fixtures_have_exact_raw_and_jcs_projection_digests() {
    assert_eq!(sha256_hex_v1(CASES_BYTES), CASES_RAW_SHA256);
    assert_eq!(sha256_hex_v1(EXPECTED_BYTES), EXPECTED_RAW_SHA256);

    let cases = parse_json_v1(CASES_BYTES);
    let expected = parse_json_v1(EXPECTED_BYTES);
    assert_eq!(jcs_sha256_hex_v1(&cases), CASES_JCS_SHA256);
    assert_eq!(jcs_sha256_hex_v1(&expected), EXPECTED_JCS_SHA256);

    let cases = exact_object_v1(
        &cases,
        &[
            "base_envelopes",
            "cases",
            "contract_version",
            "coverage",
            "description",
            "mutation_vocabulary",
            "schema",
            "verification_keys",
        ],
    );
    let expected = exact_object_v1(
        &expected,
        &[
            "authority_vocabulary",
            "case_count",
            "contract_version",
            "outcomes",
            "result_vocabulary",
            "schema",
        ],
    );
    assert_eq!(
        required_str_v1(cases, "schema"),
        "helixos.durable-dispatch-fixtures/1"
    );
    assert_eq!(
        required_str_v1(expected, "schema"),
        "helixos.durable-dispatch-expected-outcomes/1"
    );
    assert_eq!(required_u64_v1(expected, "case_count"), 143);

    let case_rows = required_array_v1(cases, "cases");
    let outcome_rows = required_array_v1(expected, "outcomes");
    assert_eq!(case_rows.len(), 143);
    assert_eq!(outcome_rows.len(), 143);

    let mut ids = BTreeSet::new();
    let mut raw_transform_count = 0_usize;
    for (case, outcome) in case_rows.iter().zip(outcome_rows) {
        let case = exact_object_v1(
            case,
            &["base", "contract", "expected_outcome_id", "id", "mutation"],
        );
        let outcome = exact_object_v1(outcome, &["authority", "id", "reason", "result", "stage"]);
        let id = required_str_v1(case, "id");
        assert!(ids.insert(id));
        assert_eq!(required_str_v1(outcome, "id"), id);
        assert_eq!(required_str_v1(case, "expected_outcome_id"), id);
        assert!(matches!(
            required_str_v1(case, "contract"),
            "grant" | "receipt"
        ));
        assert!(matches!(
            required_str_v1(outcome, "result"),
            "ACCEPT_GRANT" | "ACCEPT_RECEIPT" | "DENY"
        ));
        assert!(matches!(
            required_str_v1(outcome, "authority"),
            "NONE" | "GRANT_ONLY" | "CONSUMED_EVIDENCE" | "DEFINITE_REFUSAL_EVIDENCE"
        ));

        let mutation = case
            .get("mutation")
            .and_then(Value::as_object)
            .expect("mutation is an object");
        match required_str_v1(mutation, "op") {
            "none" | "remove" => exact_keys_v1(mutation, &["op", "path"]),
            "add" | "replace" => exact_keys_v1(mutation, &["op", "path", "value"]),
            "raw-transform" => {
                raw_transform_count += 1;
                exact_keys_v1(mutation, &["op", "path", "value"]);
                assert_eq!(required_str_v1(mutation, "path"), "");
            }
            other => panic!("mutation vocabulary escaped the closed corpus: {other}"),
        }
    }
    assert_eq!(ids.len(), 143);
    assert_eq!(raw_transform_count, 12);
}

#[test]
fn end_to_end_fixture_is_exact_jcs_and_all_six_members_are_closed() {
    assert_eq!(sha256_hex_v1(END_TO_END_BYTES), END_TO_END_SHA256);
    let manifest = parse_json_v1(END_TO_END_BYTES);
    assert_eq!(canonical_bytes_v1(&manifest), END_TO_END_BYTES);
    let root = exact_object_v1(
        &manifest,
        &["case_count", "cases", "contract_version", "schema"],
    );
    assert_eq!(required_u64_v1(root, "case_count"), 6);
    assert_eq!(required_u64_v1(root, "contract_version"), 1);
    assert_eq!(
        required_str_v1(root, "schema"),
        "helixos.durable-dispatch-end-to-end-cases/1"
    );

    let rows = required_array_v1(root, "cases");
    assert_eq!(rows.len(), SCENARIOS.len());
    for (row, expected) in rows.iter().zip(SCENARIOS) {
        let row = exact_object_v1(row, &SCENARIO_MEMBER_KEYS);
        assert_eq!(required_u64_v1(row, "ordinal"), expected.ordinal);
        assert_eq!(required_str_v1(row, "id"), expected.id);
        assert_eq!(required_str_v1(row, "execution"), expected.execution);
        assert_eq!(
            required_str_v1(row, "durable_evidence"),
            "cross-store-production-facade"
        );
        assert_eq!(
            required_str_v1(row, "durable_projection"),
            expected.durable_projection
        );
        assert_eq!(required_str_v1(row, "outcome"), expected.outcome);
        assert_eq!(required_str_v1(row, "state"), expected.state);
        assert_eq!(
            required_str_v1(row, "control_state"),
            expected.control_state
        );
        assert_eq!(required_str_v1(row, "evidence_scope"), "subsystem-only");
        assert!(required_bool_v1(row, "subsystem_only"));
        assert!(!required_bool_v1(row, "effect_authorized"));
        assert!(!required_bool_v1(row, "activation_authorized"));
        assert_eq!(required_u64_v1(row, "host_effect_count"), 0);
        assert_eq!(required_u64_v1(row, "automatic_redelivery_count"), 0);
        assert_eq!(required_u64_v1(row, "replacement_grant_count"), 0);
    }
}

#[test]
fn four_portable_scenarios_use_ordinary_production_paths_with_no_effect() {
    let shared = Arc::new(CorpusStateV1::default());
    let store = CorpusStoreV1 {
        shared: Arc::clone(&shared),
    };
    let entropy = DeterministicEntropyV1::default();

    let dispatch = dispatch_prepared_once_v1(
        &store,
        dispatch_request_v1(),
        &DeterministicAuthorityV1,
        &entropy,
        &DeterministicGrantSignerV1,
        &DeterministicGuardProviderV1,
    );
    let retained_grant_id = match dispatch {
        DispatchRequestOutcomeV1::Dispatched(retained) => retained.grant_id(),
        other => panic!("ordinary production dispatch did not commit: {other:?}"),
    };
    assert_eq!(shared.dispatch_commits.load(Ordering::SeqCst), 1);
    assert_eq!(entropy.calls.load(Ordering::SeqCst), 3);

    let exact_grant = shared
        .exact_grant
        .lock()
        .expect("corpus grant lock")
        .clone()
        .expect("dispatch retained exact grant bytes");
    let grant_binding = shared
        .grant_binding
        .lock()
        .expect("corpus grant binding lock")
        .expect("dispatch retained exact grant binding");
    assert_eq!(retained_grant_id, grant_binding);
    assert_ne!(grant_binding, [0x61; 32]);
    let inbox = DeterministicInboxV1::new(exact_grant.clone(), grant_binding);
    let consume = receive_and_consume_exact_grant_v1(&inbox, &exact_grant);
    assert!(matches!(
        consume,
        DispatchInboxAdapterOutcomeV1::Consumed(DeterministicReceiptV1(1))
    ));
    assert_eq!(inbox.receive_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inbox.consume_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        inbox.readback_grant_v1(&[0x61; 32]),
        DispatchInboxReadbackOutcomeV1::Conflict
    ));
    let lost_ack =
        recover_lost_acknowledgement_v1(&inbox, &grant_binding, &exact_grant, 5_000, 5_001);
    assert!(matches!(
        lost_ack,
        DispatchLostAcknowledgementRecoveryV1::RetainedReceipt {
            receipt: DeterministicReceiptV1(1),
            evidence_only: true,
        }
    ));
    assert_eq!(inbox.receive_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inbox.consume_calls.load(Ordering::SeqCst), 1);

    let absent = AlwaysAbsentInboxV1::new(grant_binding);
    assert!(matches!(
        absent.readback_grant_v1(&[0x61; 32]),
        DispatchInboxReadbackOutcomeV1::Conflict
    ));
    let gate = OneSequenceGateV1::default();
    let mut schedule = DeterministicScheduleV1::default();
    let unknown = run_automatic_readback_once_v1(
        &absent,
        &gate,
        &mut schedule,
        37,
        DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
        &grant_binding,
        1_000,
        2_000,
        2_000,
    );
    assert!(matches!(
        unknown,
        DispatchAutomaticReadbackOutcomeV1::OutcomeUnknownThenReconciliationRequired {
            unknown_reason: DispatchUnknownReasonV1::ReadbackExhausted,
            reconciliation_reason: DispatchReconciliationReasonV1::PossibleConsumption,
        }
    ));
    assert_eq!(absent.readback_calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        schedule.calls,
        [
            (1_000, 1_500),
            (1_025, 1_500),
            (1_100, 1_500),
            (1_275, 1_500)
        ]
    );
    assert!(matches!(
        run_automatic_readback_once_v1(
            &absent,
            &gate,
            &mut schedule,
            37,
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &[0x61; 32],
            1_000,
            2_000,
            2_000,
        ),
        DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
    ));
    assert_eq!(absent.readback_calls.load(Ordering::SeqCst), 4);
}

#[test]
fn fault_fixture_and_authoritative_registry_are_exact_ordered_and_complete() {
    assert_eq!(sha256_hex_v1(FAULT_FIXTURE_BYTES), FAULT_FIXTURE_RAW_SHA256);
    assert_eq!(
        sha256_hex_v1(FAULT_REGISTRY_BYTES),
        FAULT_REGISTRY_RAW_SHA256
    );
    let fixture = parse_json_v1(FAULT_FIXTURE_BYTES);
    let registry = parse_json_v1(FAULT_REGISTRY_BYTES);
    assert_eq!(jcs_sha256_hex_v1(&fixture), FAULT_FIXTURE_JCS_SHA256);
    assert_eq!(jcs_sha256_hex_v1(&registry), FAULT_REGISTRY_JCS_SHA256);

    let fixture = fixture.as_object().expect("fault fixture object");
    let registry = registry.as_object().expect("fault registry object");
    assert_eq!(required_u64_v1(fixture, "boundary_count"), 90);
    assert_eq!(required_u64_v1(fixture, "declared_case_count"), 180);
    assert_eq!(required_u64_v1(registry, "boundary_count"), 90);
    assert_eq!(required_u64_v1(registry, "required_case_count"), 180);
    assert_eq!(
        required_str_v1(fixture, "authoritative_sha256"),
        FAULT_REGISTRY_RAW_SHA256
    );
    assert_eq!(
        fixture.get("plan004_registry"),
        registry.get("plan004_registry")
    );

    let fixture_boundaries = required_array_v1(fixture, "boundaries");
    let registry_boundaries = required_array_v1(registry, "boundaries");
    assert_eq!(fixture_boundaries, registry_boundaries);
    assert_eq!(fixture_boundaries.len(), 90);
    for (index, boundary) in fixture_boundaries.iter().enumerate() {
        let boundary = boundary.as_object().expect("boundary object");
        let ordinal = u64::try_from(index + 1).expect("90 ordinals fit u64");
        assert_eq!(required_u64_v1(boundary, "ordinal"), ordinal);
        assert_eq!(
            required_str_v1(boundary, "id"),
            format!("PLAN005-FB-{ordinal:03}")
        );
        assert_eq!(
            required_array_v1(boundary, "coverage"),
            [
                Value::String("in-process".into()),
                Value::String("process-kill".into())
            ]
        );
    }

    let cases = required_array_v1(fixture, "cases");
    assert_eq!(cases.len(), 180);
    for (index, case) in cases.iter().enumerate() {
        let case = case.as_object().expect("fault case object");
        let case_ordinal = u64::try_from(index + 1).expect("180 ordinals fit u64");
        let boundary_ordinal = u64::try_from(index / 2 + 1).expect("90 ordinals fit u64");
        let boundary_id = format!("PLAN005-FB-{boundary_ordinal:03}");
        let mode = if index % 2 == 0 {
            "in-process"
        } else {
            "process-kill"
        };
        assert_eq!(required_u64_v1(case, "case_ordinal"), case_ordinal);
        assert_eq!(required_u64_v1(case, "boundary_ordinal"), boundary_ordinal);
        assert_eq!(required_str_v1(case, "boundary_id"), boundary_id);
        assert_eq!(
            required_str_v1(case, "case_id"),
            format!("{boundary_id}::{mode}")
        );
        assert_eq!(required_str_v1(case, "mode"), mode);
        assert_eq!(required_u64_v1(case, "expected_reach_count"), 1);
        assert_eq!(required_u64_v1(case, "expected_injection_count"), 1);
        assert_eq!(
            required_array_v1(case, "selected_boundary_ids"),
            [Value::String(boundary_id)]
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn compiled_feature_registry_accepts_each_exact_id_and_injects_once() {
    for ordinal in 1..=90 {
        let id = format!("PLAN005-FB-{ordinal:03}");
        let disabled = DispatchFaultProbeV1::disabled_v1();
        assert_eq!(
            disabled.reach_id_v1(&id),
            Ok(FaultInjectionDecisionV1::Continue)
        );

        let selected =
            DispatchFaultProbeV1::selected_v1(&id, 1, FaultInjectionModeV1::InProcess, || {})
                .expect("fixture ID selects the compiled production registry");
        assert_eq!(
            selected.reach_id_v1(&id),
            Ok(FaultInjectionDecisionV1::InjectInProcess)
        );
        assert_eq!(
            selected.reach_id_v1(&id),
            Ok(FaultInjectionDecisionV1::Continue)
        );
        assert!(selected.injected_v1());
    }
}

fn parse_json_v1(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("frozen fixture parses")
}

fn canonical_bytes_v1(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("frozen fixture canonicalizes")
}

fn sha256_hex_v1(bytes: &[u8]) -> String {
    Sha256Digest::digest(bytes).to_hex()
}

fn jcs_sha256_hex_v1(value: &Value) -> String {
    sha256_hex_v1(&canonical_bytes_v1(value))
}

fn exact_object_v1<'value>(value: &'value Value, keys: &[&str]) -> &'value Map<String, Value> {
    let object = value.as_object().expect("fixture value is an object");
    exact_keys_v1(object, keys);
    object
}

fn exact_keys_v1(object: &Map<String, Value>, keys: &[&str]) {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = keys.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "fixture member set drift");
}

fn required_array_v1<'value>(object: &'value Map<String, Value>, key: &str) -> &'value [Value] {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .expect("fixture array exists")
}

fn required_str_v1<'value>(object: &'value Map<String, Value>, key: &str) -> &'value str {
    object
        .get(key)
        .and_then(Value::as_str)
        .expect("fixture string exists")
}

fn required_u64_v1(object: &Map<String, Value>, key: &str) -> u64 {
    object
        .get(key)
        .and_then(Value::as_u64)
        .expect("fixture integer exists")
}

fn required_bool_v1(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_bool)
        .expect("fixture boolean exists")
}

#[derive(Default)]
struct CorpusStateV1 {
    exact_grant: Mutex<Option<Vec<u8>>>,
    grant_binding: Mutex<Option<[u8; 32]>>,
    dispatch_commits: AtomicUsize,
}

struct DeterministicReloadedV1;

impl DispatchReloadedCandidateV1 for DeterministicReloadedV1 {
    fn effect_descriptor_v1(&self) -> Option<DispatchEffectDescriptorV1> {
        Some(effect_descriptor_v1())
    }

    fn required_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
        DispatchCapacityVectorV1::try_new(10, 20, 30, 40).ok()
    }

    fn held_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
        DispatchCapacityVectorV1::try_new(10, 20, 30, 40).ok()
    }

    fn prior_dispatch_projection_v1(&self) -> Option<DispatchRetainedProjectionV1> {
        None
    }
}

struct DeterministicCommitEvidenceV1 {
    grant_id: [u8; 32],
    grant_digest: [u8; 32],
}

impl DispatchCommitEvidenceV1 for DeterministicCommitEvidenceV1 {
    fn grant_id_v1(&self) -> [u8; 32] {
        self.grant_id
    }

    fn grant_digest_v1(&self) -> [u8; 32] {
        self.grant_digest
    }

    fn state_generation_v1(&self) -> u64 {
        7
    }
}

struct CorpusStoreV1 {
    shared: Arc<CorpusStateV1>,
}

impl DispatchCoordinatorStoreV1 for CorpusStoreV1 {
    type ReloadedState = DeterministicReloadedV1;
    type CommitReceipt = DeterministicCommitEvidenceV1;
    type UncertainCommitCustody = ();
    type ReadbackEvidence = DeterministicCommitEvidenceV1;

    fn reload_authoritative_v1(
        &self,
        _request: &DispatchLookupRequestV1,
    ) -> DispatchReloadOutcomeV1<Self::ReloadedState> {
        DispatchReloadOutcomeV1::Ready(DeterministicReloadedV1)
    }

    fn commit_candidate_once_v1(
        &self,
        candidate: DispatchCommitCandidateV1<Self::ReloadedState>,
    ) -> DispatchStoreCommitClassificationV1<Self::CommitReceipt, Self::UncertainCommitCustody>
    {
        assert_eq!(candidate.operation_id(), "operation-v1");
        let exact = candidate.exact_grant().exact_bytes();
        assert!(!exact.is_empty());
        let grant_id = *candidate
            .exact_grant()
            .signed()
            .protected()
            .grant_id()
            .as_bytes();
        let grant_digest = *candidate.exact_grant().signed().grant_digest().as_bytes();
        *self.shared.exact_grant.lock().expect("corpus grant lock") = Some(exact.to_vec());
        *self
            .shared
            .grant_binding
            .lock()
            .expect("corpus grant binding lock") = Some(grant_id);
        assert_eq!(
            self.shared.dispatch_commits.fetch_add(1, Ordering::SeqCst),
            0,
            "one scenario may commit one grant only"
        );
        DispatchStoreCommitClassificationV1::Committed(DeterministicCommitEvidenceV1 {
            grant_id,
            grant_digest,
        })
    }

    fn readback_uncertain_v1(
        &self,
        _custody: Self::UncertainCommitCustody,
    ) -> DispatchStoreReadbackOutcomeV1<Self::ReadbackEvidence> {
        panic!("the deterministic committed scenario never enters uncertain readback")
    }
}

#[derive(Default)]
struct DeterministicEntropyV1 {
    calls: AtomicUsize,
}

impl DispatchEntropySourceV1 for DeterministicEntropyV1 {
    fn fill_entropy_v1(
        &self,
        domain: DispatchEntropyDomainV1,
        destination: &mut [u8],
    ) -> Result<(), DispatchEntropyErrorV1> {
        let byte = match domain {
            DispatchEntropyDomainV1::AttemptIdentity => 0x41,
            DispatchEntropyDomainV1::GrantIdentity => 0x42,
            DispatchEntropyDomainV1::OneShotNonce => 0x43,
            DispatchEntropyDomainV1::TraceIdentity => 0x44,
        };
        destination.fill(byte);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct DeterministicGrantSignerV1;

impl GrantSigner for DeterministicGrantSignerV1 {
    fn key_id(&self) -> &str {
        "dispatch-key-v1"
    }

    fn sign_execution_grant(&self, message: &[u8]) -> Result<[u8; 64], ContractError> {
        assert!(message.starts_with(b"HELIXOS\0EXECUTION-GRANT\0V1\0"));
        Ok([0x55; 64])
    }
}

struct DeterministicAuthorityV1;

impl DispatchAuthorityProviderV1 for DeterministicAuthorityV1 {
    fn capture_authority_v1(
        &self,
        phase: DispatchAuthorityCapturePhaseV1,
        _request: &DispatchLookupRequestV1,
        _attempt: &helix_plan_dispatch::DispatchAttemptIdV1,
    ) -> DispatchAuthorityCaptureOutcomeV1 {
        DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(authority_view_v1(phase)))
    }
}

struct DeterministicPermitV1;

impl DispatchCommitPermitV1 for DeterministicPermitV1 {
    fn deadline_monotonic_ms(&self) -> u64 {
        375
    }

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        if now_monotonic_ms < self.deadline_monotonic_ms() {
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
            DispatchStoreCommitClassificationV1::Committed(value) => {
                DispatchCommitResolutionV1::Committed(value)
            }
            DispatchStoreCommitClassificationV1::PriorExactDispatch(value) => {
                DispatchCommitResolutionV1::PriorExactDispatch(value)
            }
            DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                DispatchCommitResolutionV1::ConfirmedRollback
            }
            DispatchStoreCommitClassificationV1::Uncertain(value) => {
                DispatchCommitResolutionV1::Uncertain(value)
            }
            DispatchStoreCommitClassificationV1::Conflict => DispatchCommitResolutionV1::Conflict,
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

struct DeterministicGuardsV1;

impl DispatchGuardSetV1 for DeterministicGuardsV1 {
    type Permit = DeterministicPermitV1;

    fn capture_final_authority_v1(&mut self) -> DispatchAuthorityCaptureOutcomeV1 {
        DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(authority_view_v1(
            DispatchAuthorityCapturePhaseV1::FinalGuarded,
        )))
    }

    fn validate_all_v1(&mut self, _now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        DispatchGuardValidationV1::Valid
    }

    fn acquire_commit_permit_v1(
        &mut self,
        _attempt: &helix_plan_dispatch::DispatchAttemptIdV1,
        _deadline_monotonic_ms: u64,
    ) -> DispatchCommitPermitOutcomeV1<Self::Permit> {
        DispatchCommitPermitOutcomeV1::Permitted(DeterministicPermitV1)
    }

    fn release_reverse_v1(self) {}
}

struct DeterministicGuardProviderV1;

impl DispatchGuardProviderV1 for DeterministicGuardProviderV1 {
    type GuardSet = DeterministicGuardsV1;

    fn acquire_in_fixed_order_v1(
        &self,
        _request: &DispatchLookupRequestV1,
        _attempt: &helix_plan_dispatch::DispatchAttemptIdV1,
        after_acquisition: &mut dyn FnMut(
            DispatchGuardClassV1,
        ) -> Result<(), DispatchGuardOrderErrorV1>,
    ) -> DispatchGuardAcquisitionV1<Self::GuardSet> {
        for guard in DispatchGuardClassV1::acquisition_order() {
            if after_acquisition(guard).is_err() {
                return DispatchGuardAcquisitionV1::OrderViolated;
            }
        }
        DispatchGuardAcquisitionV1::Acquired(DeterministicGuardsV1)
    }
}

fn dispatch_request_v1() -> DispatchLookupRequestV1 {
    DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
        contract_version: 1,
        operation_id: "operation-v1",
        expected_plan_digest: [1; 32],
        expected_preparation_attempt_digest: [2; 32],
        expected_preparation_transition_generation: 3,
        caller_deadline_monotonic_ms: 4_000,
    })
    .expect("deterministic lookup is bounded")
}

fn effect_descriptor_v1() -> DispatchEffectDescriptorV1 {
    DispatchEffectDescriptorV1::try_new(DispatchEffectDescriptorInputV1 {
        operation_state_generation: 9,
        target: ResourceRefV1::try_new("workspace", vec!["file.txt".to_owned()])
            .expect("portable target"),
        precondition_digest: Sha256Digest::from_bytes([3; 32]),
        content_digest: Sha256Digest::from_bytes([4; 32]),
        content_byte_length: 16,
        content_media_type: "text/plain".to_owned(),
    })
    .expect("deterministic descriptor is bounded")
}

fn authority_view_v1(phase: DispatchAuthorityCapturePhaseV1) -> DispatchAuthorityViewV1 {
    let sample = match phase {
        DispatchAuthorityCapturePhaseV1::Preliminary => 100,
        DispatchAuthorityCapturePhaseV1::FinalGuarded => 125,
    };
    DispatchAuthorityViewV1::try_new(DispatchAuthorityViewInputV1 {
        contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
        phase,
        time: DispatchTimeCaptureV1::new(
            identifier_v1("boot-v1"),
            generation_v1(30),
            safe_u64_v1(1_000_000 + sample),
            safe_u64_v1(sample),
        ),
        task_id: identifier_v1("task-v1"),
        workload_id: identifier_v1("workload-v1"),
        instance_epoch: safe_u64_v1(14),
        supervisor_epoch: safe_u64_v1(15),
        supervisor_generation: generation_v1(16),
        trust_generation: generation_v1(17),
        verified_key_fingerprint: digest_v1(1),
        workload_generation: generation_v1(18),
        workload_evidence_digest: digest_v1(2),
        lease_generation: generation_v1(19),
        lease_digest: digest_v1(3),
        lease_decision_digest: digest_v1(4),
        authorization_generation: generation_v1(20),
        authorization_evidence_digest: digest_v1(5),
        policy_generation: generation_v1(21),
        policy_decision_generation: generation_v1(22),
        policy_content_digest: digest_v1(6),
        policy_decision_digest: digest_v1(7),
        catalogue_generation: generation_v1(23),
        catalogue_decision_generation: generation_v1(24),
        catalogue_content_digest: digest_v1(8),
        catalogue_decision_digest: digest_v1(9),
        capability_report_generation: generation_v1(25),
        capability_report_digest: digest_v1(10),
        host_driver_context_digest: digest_v1(11),
        capability_observed_at_utc_ms: safe_u64_v1(999_900),
        capability_max_age_ms: safe_u64_v1(500),
        adapter_capability_digest: digest_v1(12),
        replay_claim_id: digest_v1(13),
        replay_claimant_generation: generation_v1(26),
        replay_binding_digest: digest_v1(14),
        budget_scope_id: identifier_v1("budget-v1"),
        budget_scope_generation: generation_v1(27),
        budget_scope_binding_digest: digest_v1(15),
        reservation_id: identifier_v1("reservation-v1"),
        reservation_generation: generation_v1(28),
        reservation_binding_digest: digest_v1(16),
        reservation_vector_digest: digest_v1(17),
        recovery_reference_digest: digest_v1(18),
        recovery_mode: RecoveryModeV1::Compensation,
        recovery_profile_digest: digest_v1(19),
        recovery_binding_digest: digest_v1(20),
        recovery_receipt_digest: digest_v1(21),
        destination_adapter_id: identifier_v1("adapter-v1"),
        protocol_version: 1,
        signer_key_id: identifier_v1("dispatch-key-v1"),
        signer_generation: generation_v1(31),
        signer_profile_digest: digest_v1(22),
        earliest_authority_deadline_monotonic_ms: generation_v1(5_000),
    })
    .expect("deterministic authority is coherent")
}

fn digest_v1(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn generation_v1(value: u64) -> Generation {
    Generation::new(value).expect("positive deterministic generation")
}

fn safe_u64_v1(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("deterministic safe integer")
}

fn identifier_v1(value: &str) -> Identifier {
    Identifier::new(value).expect("deterministic identifier")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeterministicReceivedV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeterministicReceiptV1(u8);

struct DeterministicInboxV1 {
    exact_grant: Vec<u8>,
    grant_binding: [u8; 32],
    consumed: AtomicBool,
    receive_calls: AtomicUsize,
    consume_calls: AtomicUsize,
}

impl DeterministicInboxV1 {
    fn new(exact_grant: Vec<u8>, grant_binding: [u8; 32]) -> Self {
        Self {
            exact_grant,
            grant_binding,
            consumed: AtomicBool::new(false),
            receive_calls: AtomicUsize::new(0),
            consume_calls: AtomicUsize::new(0),
        }
    }
}

impl DispatchInboxV1 for DeterministicInboxV1 {
    type RetainedState = DeterministicReceivedV1;
    type RetainedReceipt = DeterministicReceiptV1;

    fn receive_exact_grant_v1(
        &self,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        assert_eq!(exact_signed_grant_bytes, self.exact_grant);
        self.receive_calls.fetch_add(1, Ordering::SeqCst);
        if self.consumed.load(Ordering::SeqCst) {
            DispatchInboxReceiveOutcomeV1::RetainedReceipt(DeterministicReceiptV1(1))
        } else {
            DispatchInboxReceiveOutcomeV1::DurablyReceived(DeterministicReceivedV1)
        }
    }
}

impl DispatchInboxConsumerV1 for DeterministicInboxV1 {
    fn consume_received_once_v1(
        &self,
        _retained_state: Self::RetainedState,
    ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
        assert!(!self.consumed.swap(true, Ordering::SeqCst));
        self.consume_calls.fetch_add(1, Ordering::SeqCst);
        DispatchInboxConsumeOutcomeV1::Consumed(DeterministicReceiptV1(1))
    }
}

impl DispatchInboxReadbackV1 for DeterministicInboxV1 {
    type RetainedState = DeterministicReceivedV1;
    type RetainedReceipt = DeterministicReceiptV1;

    fn readback_grant_v1(
        &self,
        grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        if grant_binding != &self.grant_binding {
            return DispatchInboxReadbackOutcomeV1::Conflict;
        }
        if self.consumed.load(Ordering::SeqCst) {
            DispatchInboxReadbackOutcomeV1::RetainedReceipt(DeterministicReceiptV1(1))
        } else {
            DispatchInboxReadbackOutcomeV1::Received(DeterministicReceivedV1)
        }
    }
}

struct AlwaysAbsentInboxV1 {
    grant_binding: [u8; 32],
    readback_calls: AtomicUsize,
}

impl AlwaysAbsentInboxV1 {
    fn new(grant_binding: [u8; 32]) -> Self {
        Self {
            grant_binding,
            readback_calls: AtomicUsize::new(0),
        }
    }
}

impl DispatchInboxReadbackV1 for AlwaysAbsentInboxV1 {
    type RetainedState = ();
    type RetainedReceipt = ();

    fn readback_grant_v1(
        &self,
        grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        if grant_binding != &self.grant_binding {
            return DispatchInboxReadbackOutcomeV1::Conflict;
        }
        self.readback_calls.fetch_add(1, Ordering::SeqCst);
        DispatchInboxReadbackOutcomeV1::Absent
    }
}

#[derive(Default)]
struct OneSequenceGateV1 {
    claimed: AtomicBool,
}

impl DispatchAutomaticReadbackGateV1 for OneSequenceGateV1 {
    fn try_begin_automatic_readback_once_v1(&self, _delivery_attempt_generation: u64) -> bool {
        !self.claimed.swap(true, Ordering::SeqCst)
    }
}

#[derive(Default)]
struct DeterministicScheduleV1 {
    calls: Vec<(u64, u64)>,
}

impl DispatchAutomaticReadbackScheduleV1 for DeterministicScheduleV1 {
    fn wait_until_readback_offset_v1(
        &mut self,
        requested_monotonic_ms: u64,
        effective_end_monotonic_ms: u64,
    ) -> DispatchReadbackWaitOutcomeV1 {
        self.calls
            .push((requested_monotonic_ms, effective_end_monotonic_ms));
        DispatchReadbackWaitOutcomeV1::ObservedAt(requested_monotonic_ms)
    }
}
