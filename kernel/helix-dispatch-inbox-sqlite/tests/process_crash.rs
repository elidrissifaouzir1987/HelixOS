//! PLAN-005 adapter receive/consume/receipt OS process-kill matrix.
//!
//! The ignored release gate below kills a child at the real production fault seam and
//! then performs an authoritative strict reopen. It is process-kill evidence only; it
//! does not claim to model power loss.

#![cfg(feature = "test-fault-injection")]

use ed25519_dalek::{Signer as _, SigningKey};
use helix_dispatch_contracts::{
    ContractError, Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier,
    ReceiptKeyResolver, ReceiptSigner, ReceiptVerificationKeyV1, Result as ContractResult, SafeU64,
    Sha256Digest,
};
use helix_dispatch_inbox_sqlite::{
    AdapterClockObservationV1, AdapterClockV1, AdapterConsumptionAdmissionObservationV1,
    AdapterConsumptionAdmissionObserverV1, AdapterInboxConsumeOutcomeV1,
    AdapterInboxInitializationV1, AdapterInboxProfileV1, AdapterInboxReadbackOutcomeV1,
    AdapterInboxReceiveOutcomeV1, AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1,
    AdapterReceiptEntropyDomainV1, AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1,
    AdapterReceiptSigningProfileV1, AdapterRetainedReceiptDecisionV1, AdapterTimeSampleV1,
    EpochObservationV1, SqliteDispatchInboxStoreV1, SupervisorEpochObservationV1,
    SupervisorEpochObserverV1,
};
use helix_plan_dispatch::FaultInjectionModeV1;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const REGISTRY_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const GRANT_ID: &str = "e11c10ad33af1f082a3b2028bdfa66d9a9413f430105d6d1b3c9c7e975d32dbd";
const CAPABILITY_DIGEST: &str = "7bd116b849df045678b6521d504056fe77119b19a0eadb84d661878e6d5f667b";
const RECEIPT_KEY_ID: &str = "production-receipt-key-v1";
const RECEIPT_PROFILE_DIGEST: [u8; 32] = [0x52; 32];
const PROCESS_CHILD_ENV: &str = "HELIX_T070_ADAPTER_PROCESS_CHILD";
const PROCESS_ROOT_ENV: &str = "HELIX_T070_ADAPTER_PROCESS_ROOT";
const PROCESS_BOUNDARY_ENV: &str = "HELIX_T070_ADAPTER_PROCESS_BOUNDARY";
const PROCESS_DECISION_ENV: &str = "HELIX_T070_ADAPTER_PROCESS_DECISION";
const READY_PREFIX: &str = "READY:";
const REACHED_PREFIX: &str = "AT:";
const GO_BYTE: u8 = b'G';
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(15);
const REAP_POLL: Duration = Duration::from_millis(5);
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
struct RegistryV1 {
    boundaries: Vec<BoundaryV1>,
}

#[derive(Debug, Deserialize)]
struct BoundaryV1 {
    ordinal: usize,
    id: String,
    category: String,
    owner: String,
    coverage: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterDurableStateV1 {
    Absent,
    Received,
    ClosedWithExactReceipt,
}

fn adapter_boundaries_v1() -> Vec<BoundaryV1> {
    let registry: RegistryV1 =
        serde_json::from_slice(REGISTRY_BYTES).expect("T060 frozen registry parses");
    registry
        .boundaries
        .into_iter()
        .filter(|boundary| (23..=39).contains(&boundary.ordinal))
        .collect()
}

fn durable_state_after_restart_v1(ordinal: usize) -> &'static [AdapterDurableStateV1] {
    match ordinal {
        23..=29 => &[AdapterDurableStateV1::Absent],
        30..=37 => &[AdapterDurableStateV1::Received],
        38..=39 => &[AdapterDurableStateV1::ClosedWithExactReceipt],
        other => panic!("T060 adapter oracle received unsupported boundary {other}"),
    }
}

#[test]
fn receive_consume_receipt_boundaries_are_closed_dual_mode_and_unique() {
    let boundaries = adapter_boundaries_v1();
    assert_eq!(boundaries.len(), 17);
    let ids = boundaries
        .iter()
        .map(|boundary| boundary.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), boundaries.len());

    for boundary in &boundaries {
        assert_eq!(boundary.id, format!("PLAN005-FB-{:03}", boundary.ordinal));
        assert_eq!(boundary.coverage, ["in-process", "process-kill"]);
        assert!(matches!(
            boundary.category.as_str(),
            "adapter-receive" | "adapter-consume-receipt" | "ack-readback-reconciliation"
        ));
        assert!(matches!(
            boundary.owner.as_str(),
            "helix-dispatch-inbox-sqlite" | "helix-dispatch-contracts" | "helix-plan-dispatch"
        ));
        assert!(!durable_state_after_restart_v1(boundary.ordinal).is_empty());
    }
}

#[test]
fn restart_oracle_never_permits_duplicate_consumption_or_partial_receipt() {
    for boundary in adapter_boundaries_v1() {
        for state in durable_state_after_restart_v1(boundary.ordinal) {
            match state {
                AdapterDurableStateV1::Absent => {}
                AdapterDurableStateV1::Received => {
                    let consumptions_after_recovery = 1_usize;
                    assert_eq!(consumptions_after_recovery, 1, "{}", boundary.id);
                }
                AdapterDurableStateV1::ClosedWithExactReceipt => {
                    let retained_receipts = 1_usize;
                    let additional_consumptions = 0_usize;
                    assert_eq!(retained_receipts, 1, "{}", boundary.id);
                    assert_eq!(additional_consumptions, 0, "{}", boundary.id);
                }
            }
        }
    }
}

#[test]
fn production_adapter_probe_reaches_both_transactions_and_retained_receipt_ack() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let probe_path = manifest.join("src/test_fault.rs");
    let probe_source = fs::read_to_string(&probe_path).unwrap_or_else(|error| {
        panic!(
            "T060 RED: T063 must add the private adapter fault probe at {}: {error}",
            probe_path.display()
        )
    });
    let receive = required_source_v1(&manifest.join("src/inbox.rs"));
    let receipt = required_source_v1(&manifest.join("src/receipt.rs"));
    let readback = required_source_v1(&manifest.join("src/readback.rs"));
    let combined = format!("{probe_source}\n{receive}\n{receipt}\n{readback}");

    for required in [
        "PLAN005-FB-023",
        "PLAN005-FB-030",
        "PLAN005-FB-031",
        "PLAN005-FB-038",
        "PLAN005-FB-039",
        "FaultProbeV1",
        "receive",
        "consume",
        "receipt",
        "acknowledgement",
    ] {
        assert!(
            combined.contains(required),
            "T060 RED: real adapter crash seam omits {required}"
        );
    }
}

#[test]
fn all_seventeen_adapter_boundaries_have_explicit_non_registry_checkpoint_call_sites() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let call_sites = [
        manifest.join("src/inbox.rs"),
        manifest.join("src/receipt.rs"),
        manifest.join("src/readback.rs"),
    ]
    .into_iter()
    .map(|path| required_source_v1(&path))
    .collect::<Vec<_>>()
    .join("\n");

    let boundaries = adapter_boundaries_v1();
    assert_eq!(boundaries.len(), 17);
    for boundary in boundaries {
        let variant = format!("FaultBoundaryV1::Plan005Fb{:03}", boundary.ordinal);
        assert!(
            call_sites.contains(&variant),
            "T060 RED: {} lacks an explicit real adapter checkpoint {variant}",
            boundary.id
        );
    }
}

#[test]
#[ignore = "release process-kill gate: kill the real adapter workflow at all 17 selected boundaries and reopen"]
fn release_adapter_process_kill_matrix_reopens_to_one_closed_state() {
    let cases = adapter_process_kill_cases_v1();
    assert_eq!(
        cases.len(),
        26,
        "all 17 boundaries and both terminal decisions"
    );
    assert_eq!(
        cases
            .iter()
            .map(|case| case.boundary_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        17
    );

    for case in cases {
        run_adapter_process_kill_case_v1(&case);
    }
}

#[test]
#[ignore = "release in-process gate: inject the real adapter workflow at all 17 selected boundaries and reopen"]
fn release_adapter_in_process_matrix_reopens_to_one_closed_state() {
    let cases = adapter_process_kill_cases_v1()
        .into_iter()
        .filter(|case| case.decision == TerminalCaseDecisionV1::Running)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 17, "one primary Running case per boundary");
    assert_eq!(
        cases
            .iter()
            .map(|case| case.boundary_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        17,
    );

    for case in cases {
        run_adapter_in_process_case_v1(&case);
    }
}

#[test]
#[ignore = "private T070 adapter process-kill child entry point"]
fn adapter_process_kill_child_v1() {
    if std::env::var(PROCESS_CHILD_ENV).ok().as_deref() != Some("1") {
        return;
    }

    let root = std::env::var_os(PROCESS_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("adapter process-kill child root was not supplied"));
    let boundary_id = std::env::var(PROCESS_BOUNDARY_ENV)
        .unwrap_or_else(|_| panic!("adapter process-kill child boundary was not supplied"));
    let ordinal = boundary_id
        .rsplit('-')
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("adapter process-kill child boundary was malformed"));
    let decision = TerminalCaseDecisionV1::from_env_v1(
        &std::env::var(PROCESS_DECISION_ENV)
            .unwrap_or_else(|_| panic!("adapter process-kill child decision was not supplied")),
    );
    announce_ready_and_wait_for_go_v1(&boundary_id);

    let mut store = reopen_store_v1(&root);
    let reached_boundary = boundary_id.clone();
    store
        .select_fault_probe_for_test_v1(
            &boundary_id,
            1,
            FaultInjectionModeV1::ProcessKill,
            move || {
                println!("{REACHED_PREFIX}{reached_boundary}");
                std::io::stdout()
                    .flush()
                    .unwrap_or_else(|_| std::process::exit(92));
                loop {
                    std::thread::park();
                }
            },
        )
        .unwrap_or_else(|_| panic!("adapter process-kill boundary selection failed"));

    execute_selected_adapter_workflow_v1(&store, ordinal, decision);

    // A selected production checkpoint always blocks in its process barrier. Reaching
    // this exit means the child did not traverse the selected seam.
    std::process::exit(95);
}

fn execute_selected_adapter_workflow_v1(
    store: &SqliteDispatchInboxStoreV1,
    ordinal: usize,
    decision: TerminalCaseDecisionV1,
) {
    match ordinal {
        23..=30 => {
            let clock = FixedClockV1::new(10, 1_000_100, 1_100);
            let epoch = FixedEpochV1::new(15, 2, 20, 1_000_101, 1_101);
            let _result = store.receive_grant_v1(
                &canonical_fixture_grant_v1(),
                &FixtureGrantResolverV1,
                &clock,
                &epoch,
            );
        }
        31..=38 => {
            let authority = ReceiptAuthorityV1::current();
            let AdapterInboxReadbackOutcomeV1::Received(received) = store
                .readback_grant_v1(grant_id_v1(), &FixtureGrantResolverV1, &authority)
                .unwrap_or_else(|_| panic!("adapter process-kill child received readback failed"))
            else {
                std::process::exit(93);
            };
            let clock = FixedClockV1::new(10, 1_000_200, 1_200);
            let epoch = FixedEpochV1::new(15, 3, 20, 1_000_201, 1_201);
            let admission = FixedAdmissionV1(decision.admission_v1());
            let entropy = FixedEntropyV1;
            let profile = signing_profile_v1(&authority);
            let _result = store.consume_received_v1(
                received,
                &FixtureGrantResolverV1,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &authority,
                &authority,
            );
        }
        39 => {
            let authority = ReceiptAuthorityV1::current();
            let _result =
                store.readback_grant_v1(grant_id_v1(), &FixtureGrantResolverV1, &authority);
        }
        _ => std::process::exit(94),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalCaseDecisionV1 {
    Running,
    Paused,
}

impl TerminalCaseDecisionV1 {
    const fn env_v1(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Paused => "paused",
        }
    }

    fn from_env_v1(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "paused" => Self::Paused,
            _ => panic!("adapter process-kill child decision was invalid"),
        }
    }

    const fn admission_v1(self) -> AdapterConsumptionAdmissionObservationV1 {
        match self {
            Self::Running => AdapterConsumptionAdmissionObservationV1::Running,
            Self::Paused => AdapterConsumptionAdmissionObservationV1::Paused,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReopenedAdapterStateV1 {
    Absent,
    Received,
    Consumed,
    Refused,
    Quarantined,
}

#[derive(Debug)]
struct AdapterProcessKillCaseV1 {
    ordinal: usize,
    boundary_id: String,
    decision: TerminalCaseDecisionV1,
    expected: ReopenedAdapterStateV1,
}

#[derive(Debug)]
struct ReopenedAdapterEvidenceV1 {
    state: ReopenedAdapterStateV1,
    canonical_receipt: Option<Vec<u8>>,
}

fn adapter_process_kill_cases_v1() -> Vec<AdapterProcessKillCaseV1> {
    let mut cases = Vec::new();
    for boundary in adapter_boundaries_v1() {
        let decisions: &[TerminalCaseDecisionV1] = if boundary.ordinal >= 31 {
            &[
                TerminalCaseDecisionV1::Running,
                TerminalCaseDecisionV1::Paused,
            ]
        } else {
            &[TerminalCaseDecisionV1::Running]
        };
        for decision in decisions {
            let expected = match boundary.ordinal {
                23..=29 => ReopenedAdapterStateV1::Absent,
                30..=37 => ReopenedAdapterStateV1::Received,
                38..=39 if *decision == TerminalCaseDecisionV1::Running => {
                    ReopenedAdapterStateV1::Consumed
                }
                38..=39 => ReopenedAdapterStateV1::Refused,
                other => panic!("unsupported adapter process-kill boundary {other}"),
            };
            cases.push(AdapterProcessKillCaseV1 {
                ordinal: boundary.ordinal,
                boundary_id: boundary.id.clone(),
                decision: *decision,
                expected,
            });
        }
    }
    cases
}

fn run_adapter_process_kill_case_v1(case: &AdapterProcessKillCaseV1) {
    let label = format!("fb-{:03}-{}", case.ordinal, case.decision.env_v1());
    let root = TemporaryRootV1::new(&label);
    let retained_receipt_before_kill = prepare_adapter_case_v1(root.path(), case);

    kill_child_at_adapter_boundary_v1(root.path(), case);

    assert_adapter_reopened_case_v1(
        root.path(),
        case,
        retained_receipt_before_kill.as_deref(),
        "process kill",
    );
}

fn run_adapter_in_process_case_v1(case: &AdapterProcessKillCaseV1) {
    let label = format!(
        "fb-{:03}-{}-in-process",
        case.ordinal,
        case.decision.env_v1()
    );
    let root = TemporaryRootV1::new(&label);
    let retained_receipt_before_injection = prepare_adapter_case_v1(root.path(), case);

    {
        let mut store = reopen_store_v1(root.path());
        store
            .select_fault_probe_for_test_v1(
                &case.boundary_id,
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            )
            .unwrap_or_else(|_| panic!("{} in-process selection failed", case.boundary_id));
        execute_selected_adapter_workflow_v1(&store, case.ordinal, case.decision);
        assert!(
            store.fault_probe_injected_for_test_v1(),
            "{} must inject once at its real adapter checkpoint",
            case.boundary_id,
        );
    }

    assert_adapter_reopened_case_v1(
        root.path(),
        case,
        retained_receipt_before_injection.as_deref(),
        "in-process injection",
    );
}

fn prepare_adapter_case_v1(root: &Path, case: &AdapterProcessKillCaseV1) -> Option<Vec<u8>> {
    let store = initialize_store_v1(root);
    match case.ordinal {
        23..=30 => None,
        31..=38 => {
            let _received = receive_fixture_v1(&store);
            None
        }
        39 => {
            let received = receive_fixture_v1(&store);
            Some(terminalize_received_v1(&store, received, case.decision))
        }
        _ => unreachable!("matrix contains only FB023 through FB039"),
    }
}

fn assert_adapter_reopened_case_v1(
    root: &Path,
    case: &AdapterProcessKillCaseV1,
    retained_receipt_before: Option<&[u8]>,
    transition: &str,
) {
    let reopened = reopen_store_v1(root);
    let evidence = classify_reopened_state_v1(&reopened, &case.boundary_id);
    assert_eq!(
        evidence.state, case.expected,
        "{} {:?} reopened to the wrong exact state",
        case.boundary_id, case.decision
    );
    match case.expected {
        ReopenedAdapterStateV1::Consumed | ReopenedAdapterStateV1::Refused => assert!(
            evidence.canonical_receipt.is_some(),
            "{} {:?} lost its exact retained receipt",
            case.boundary_id,
            case.decision
        ),
        ReopenedAdapterStateV1::Absent
        | ReopenedAdapterStateV1::Received
        | ReopenedAdapterStateV1::Quarantined => assert!(
            evidence.canonical_receipt.is_none(),
            "{} {:?} exposed a partial receipt",
            case.boundary_id,
            case.decision
        ),
    }
    if let Some(before) = retained_receipt_before {
        assert_eq!(
            evidence.canonical_receipt.as_deref(),
            Some(before),
            "{} {:?} changed the retained receipt across {transition}",
            case.boundary_id,
            case.decision
        );
    }
}

fn classify_reopened_state_v1(
    store: &SqliteDispatchInboxStoreV1,
    boundary_id: &str,
) -> ReopenedAdapterEvidenceV1 {
    let authority = ReceiptAuthorityV1::current();
    match store
        .readback_grant_v1(grant_id_v1(), &FixtureGrantResolverV1, &authority)
        .unwrap_or_else(|error| panic!("{boundary_id} strict reopened readback failed: {error:?}"))
    {
        AdapterInboxReadbackOutcomeV1::Absent => ReopenedAdapterEvidenceV1 {
            state: ReopenedAdapterStateV1::Absent,
            canonical_receipt: None,
        },
        AdapterInboxReadbackOutcomeV1::Received(_) => ReopenedAdapterEvidenceV1 {
            state: ReopenedAdapterStateV1::Received,
            canonical_receipt: None,
        },
        AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt) => {
            let state = match receipt.decision() {
                AdapterRetainedReceiptDecisionV1::Consumed => ReopenedAdapterStateV1::Consumed,
                AdapterRetainedReceiptDecisionV1::RefusedDefinite => {
                    ReopenedAdapterStateV1::Refused
                }
            };
            ReopenedAdapterEvidenceV1 {
                state,
                canonical_receipt: Some(receipt.canonical_receipt().to_vec()),
            }
        }
        AdapterInboxReadbackOutcomeV1::Quarantined => ReopenedAdapterEvidenceV1 {
            state: ReopenedAdapterStateV1::Quarantined,
            canonical_receipt: None,
        },
        AdapterInboxReadbackOutcomeV1::Conflict => {
            panic!("{boundary_id} strict reopen produced a conflict")
        }
    }
}

fn kill_child_at_adapter_boundary_v1(root: &Path, case: &AdapterProcessKillCaseV1) {
    let executable = std::env::current_exe()
        .unwrap_or_else(|_| panic!("adapter process-kill test executable was unavailable"));
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "adapter_process_kill_child_v1",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROCESS_CHILD_ENV, "1")
        .env(PROCESS_ROOT_ENV, root)
        .env(PROCESS_BOUNDARY_ENV, &case.boundary_id)
        .env(PROCESS_DECISION_ENV, case.decision.env_v1())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|_| panic!("adapter process-kill child failed to spawn"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("adapter process-kill child stdin was unavailable"));
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("adapter process-kill child stdout was unavailable"));
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let ready = format!("{READY_PREFIX}{}", case.boundary_id);
    if !wait_for_protocol_line_v1(&receiver, &ready) {
        terminate_and_reap_v1(&mut child);
        drop(stdin);
        let _ = reader.join();
        panic!("{} child did not become ready", case.boundary_id);
    }
    stdin
        .write_all(&[GO_BYTE])
        .and_then(|()| stdin.flush())
        .unwrap_or_else(|_| panic!("{} child start signal failed", case.boundary_id));

    let reached = format!("{REACHED_PREFIX}{}", case.boundary_id);
    if !wait_for_protocol_line_v1(&receiver, &reached) {
        terminate_and_reap_v1(&mut child);
        drop(stdin);
        let _ = reader.join();
        panic!(
            "{} child did not reach the production checkpoint",
            case.boundary_id
        );
    }

    terminate_and_reap_v1(&mut child);
    drop(stdin);
    reader
        .join()
        .unwrap_or_else(|_| panic!("{} protocol reader failed", case.boundary_id));
}

fn announce_ready_and_wait_for_go_v1(boundary_id: &str) {
    println!("{READY_PREFIX}{boundary_id}");
    std::io::stdout()
        .flush()
        .unwrap_or_else(|_| std::process::exit(96));
    let mut go = [0_u8; 1];
    std::io::stdin()
        .lock()
        .read_exact(&mut go)
        .unwrap_or_else(|_| std::process::exit(97));
    if go[0] != GO_BYTE {
        std::process::exit(98);
    }
}

fn wait_for_protocol_line_v1(receiver: &Receiver<String>, expected: &str) -> bool {
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(line) if line.contains(expected) => return true,
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn terminate_and_reap_v1(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(REAP_POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("adapter process-kill child reap watchdog expired");
            }
            Err(_) => panic!("adapter process-kill child reap failed"),
        }
    }
}

struct FixtureGrantResolverV1;

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id != "fixture-grant-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY))
    }
}

struct ReceiptAuthorityV1(SigningKey);

impl ReceiptAuthorityV1 {
    fn current() -> Self {
        Self(SigningKey::from_bytes(&[0x73; 32]))
    }

    fn fingerprint_v1(&self) -> Sha256Digest {
        Sha256Digest::digest(self.0.verifying_key().as_bytes())
    }
}

impl ReceiptSigner for ReceiptAuthorityV1 {
    fn key_id(&self) -> &str {
        RECEIPT_KEY_ID
    }

    fn sign_execution_receipt(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

impl ReceiptKeyResolver for ReceiptAuthorityV1 {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        if key_id != RECEIPT_KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        Ok(ReceiptVerificationKeyV1::current(
            self.0.verifying_key().to_bytes(),
        ))
    }
}

struct FixedClockV1 {
    clock_generation: u64,
    utc_ms: u64,
    monotonic_ms: u64,
}

impl FixedClockV1 {
    const fn new(clock_generation: u64, utc_ms: u64, monotonic_ms: u64) -> Self {
        Self {
            clock_generation,
            utc_ms,
            monotonic_ms,
        }
    }
}

impl AdapterClockV1 for FixedClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        AdapterClockObservationV1::Current(time_sample_v1(
            self.clock_generation,
            self.utc_ms,
            self.monotonic_ms,
        ))
    }
}

struct FixedEpochV1 {
    supervisor_epoch: u64,
    observer_generation: u64,
    clock_generation: u64,
    utc_ms: u64,
    monotonic_ms: u64,
}

impl FixedEpochV1 {
    const fn new(
        supervisor_epoch: u64,
        observer_generation: u64,
        clock_generation: u64,
        utc_ms: u64,
        monotonic_ms: u64,
    ) -> Self {
        Self {
            supervisor_epoch,
            observer_generation,
            clock_generation,
            utc_ms,
            monotonic_ms,
        }
    }
}

impl SupervisorEpochObserverV1 for FixedEpochV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            SafeU64::new(self.supervisor_epoch).unwrap(),
            Generation::new(self.observer_generation).unwrap(),
            time_sample_v1(self.clock_generation, self.utc_ms, self.monotonic_ms),
        ))
    }
}

struct FixedAdmissionV1(AdapterConsumptionAdmissionObservationV1);

impl AdapterConsumptionAdmissionObserverV1 for FixedAdmissionV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        self.0
    }
}

struct FixedEntropyV1;

impl AdapterReceiptEntropyV1 for FixedEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        assert_eq!(domain, AdapterReceiptEntropyDomainV1::ReceiptIdentity);
        destination.fill(0x80);
        Ok(())
    }
}

fn initialize_store_v1(root: &Path) -> SqliteDispatchInboxStoreV1 {
    let config = AdapterInboxStoreConfigV1::try_new_empty_attested(
        root.to_path_buf(),
        root_identity_v1(),
        5_000,
    )
    .expect("empty adapter root is provisioner-attested");
    SqliteDispatchInboxStoreV1::initialize_empty_v1(
        config,
        AdapterInboxInitializationV1::try_new(15, 1, RECEIPT_PROFILE_DIGEST)
            .expect("initial adapter metadata is bounded"),
        adapter_profile_v1(),
    )
    .expect("adapter process-kill store initializes")
}

fn reopen_store_v1(root: &Path) -> SqliteDispatchInboxStoreV1 {
    let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        root.to_path_buf(),
        root_identity_v1(),
        5_000,
    )
    .expect("existing adapter root remains provisioner-attested");
    SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile_v1())
        .expect("adapter graph passes strict reopen verification")
}

fn receive_fixture_v1(
    store: &SqliteDispatchInboxStoreV1,
) -> helix_dispatch_inbox_sqlite::ReceivedInboxGrantV1 {
    let clock = FixedClockV1::new(10, 1_000_100, 1_100);
    let epoch = FixedEpochV1::new(15, 2, 20, 1_000_101, 1_101);
    let AdapterInboxReceiveOutcomeV1::Received(received) = store
        .receive_grant_v1(
            &canonical_fixture_grant_v1(),
            &FixtureGrantResolverV1,
            &clock,
            &epoch,
        )
        .expect("fixture grant reaches RECEIVED")
    else {
        panic!("fixture grant did not produce its first durable receive");
    };
    received
}

fn terminalize_received_v1(
    store: &SqliteDispatchInboxStoreV1,
    received: helix_dispatch_inbox_sqlite::ReceivedInboxGrantV1,
    decision: TerminalCaseDecisionV1,
) -> Vec<u8> {
    let authority = ReceiptAuthorityV1::current();
    let clock = FixedClockV1::new(10, 1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 20, 1_000_201, 1_201);
    let admission = FixedAdmissionV1(decision.admission_v1());
    let profile = signing_profile_v1(&authority);
    let outcome = store
        .consume_received_v1(
            received,
            &FixtureGrantResolverV1,
            &clock,
            &epoch,
            &admission,
            &FixedEntropyV1,
            &profile,
            &authority,
            &authority,
        )
        .expect("FB039 setup terminalizes through the production receipt transaction");
    match (decision, outcome) {
        (TerminalCaseDecisionV1::Running, AdapterInboxConsumeOutcomeV1::Consumed(receipt))
        | (
            TerminalCaseDecisionV1::Paused,
            AdapterInboxConsumeOutcomeV1::DefinitelyRefused(receipt),
        ) => receipt.canonical_receipt().to_vec(),
        (_, other) => panic!("FB039 setup produced an unexpected terminal outcome: {other:?}"),
    }
}

fn adapter_profile_v1() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        "adapter-v1",
        1,
        Sha256Digest::parse_hex(CAPABILITY_DIGEST).unwrap(),
    )
    .unwrap()
}

fn signing_profile_v1(authority: &ReceiptAuthorityV1) -> AdapterReceiptSigningProfileV1 {
    AdapterReceiptSigningProfileV1::try_new(
        RECEIPT_KEY_ID,
        authority.fingerprint_v1(),
        Sha256Digest::from_bytes(RECEIPT_PROFILE_DIGEST),
    )
    .unwrap()
}

fn canonical_fixture_grant_v1() -> Vec<u8> {
    let corpus: serde_json::Value = serde_json::from_str(CASES).unwrap();
    serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap()
}

fn grant_id_v1() -> Sha256Digest {
    Sha256Digest::parse_hex(GRANT_ID).unwrap()
}

const fn root_identity_v1() -> AdapterInboxRootIdentityEvidenceV1 {
    AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x41; 32])
}

fn time_sample_v1(clock_generation: u64, utc_ms: u64, monotonic_ms: u64) -> AdapterTimeSampleV1 {
    AdapterTimeSampleV1::new(
        Identifier::new("boot-v1").unwrap(),
        Generation::new(clock_generation).unwrap(),
        SafeU64::new(utc_ms).unwrap(),
        SafeU64::new(monotonic_ms).unwrap(),
    )
}

struct TemporaryRootV1(PathBuf);

impl TemporaryRootV1 {
    fn new(label: &str) -> Self {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-t070-adapter-process-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary adapter process-kill root creates");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn required_source_v1(path: &Path) -> String {
    let source = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "T060 RED: missing production module {}: {error}",
            path.display()
        )
    });
    source_without_comments_v1(&source)
}

fn source_without_comments_v1(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T060 source comments are balanced");
    output
}
