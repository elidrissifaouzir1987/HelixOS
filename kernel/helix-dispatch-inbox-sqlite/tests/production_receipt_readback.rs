//! Real SQLite T049/T050 terminalization, contention, and restart readback proofs.

use ed25519_dalek::{Signer as _, SigningKey};
use helix_dispatch_contracts::{
    ContractError, Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier,
    ReceiptKeyResolver, ReceiptSigner, ReceiptVerificationKeyV1, Result as ContractResult, SafeU64,
    Sha256Digest,
};
#[cfg(feature = "test-fault-injection")]
use helix_dispatch_inbox_sqlite::{
    classify_and_retain_adapter_connections_for_test_v1, AdapterCrossStoreIdsForTestV1,
    AdapterHistoryCustodyForTestV1, AdapterLifecycleRelationshipForTestV1,
};
use helix_dispatch_inbox_sqlite::{
    AdapterClockObservationV1, AdapterClockV1, AdapterConsumptionAdmissionObservationV1,
    AdapterConsumptionAdmissionObserverV1, AdapterInboxConsumeErrorV1,
    AdapterInboxConsumeOutcomeV1, AdapterInboxInitializationV1, AdapterInboxProfileV1,
    AdapterInboxReadbackOutcomeV1, AdapterInboxReceiveErrorV1, AdapterInboxReceiveOutcomeV1,
    AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1, AdapterReceiptEntropyDomainV1,
    AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1, AdapterReceiptSigningProfileV1,
    AdapterRetainedReceiptDecisionV1, AdapterTimeSampleV1, EpochObservationV1,
    SqliteDispatchInboxStoreV1, SupervisorEpochObservationV1, SupervisorEpochObserverV1,
};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
#[cfg(feature = "test-fault-injection")]
use std::time::Duration;

const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const GRANT_ID: &str = "e11c10ad33af1f082a3b2028bdfa66d9a9413f430105d6d1b3c9c7e975d32dbd";
const CAPABILITY_DIGEST: &str = "7bd116b849df045678b6521d504056fe77119b19a0eadb84d661878e6d5f667b";
const RECEIPT_KEY_ID: &str = "production-receipt-key-v1";
const RECEIPT_PROFILE_DIGEST: [u8; 32] = [0x52; 32];
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum TrustStatusV1 {
    Current,
    Historical,
}

struct FixtureGrantResolverV1(TrustStatusV1);

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id != "fixture-grant-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(match self.0 {
            TrustStatusV1::Current => GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY),
            TrustStatusV1::Historical => GrantVerificationKeyV1::historical(FIXTURE_GRANT_KEY),
        })
    }
}

struct ReceiptAuthorityV1 {
    key: SigningKey,
    trust: TrustStatusV1,
    signer_calls: AtomicUsize,
}

impl ReceiptAuthorityV1 {
    fn current() -> Self {
        Self {
            key: SigningKey::from_bytes(&[0x73; 32]),
            trust: TrustStatusV1::Current,
            signer_calls: AtomicUsize::new(0),
        }
    }

    fn historical_verifier(&self) -> Self {
        Self {
            key: SigningKey::from_bytes(&[0x73; 32]),
            trust: TrustStatusV1::Historical,
            signer_calls: AtomicUsize::new(0),
        }
    }

    fn fingerprint(&self) -> Sha256Digest {
        Sha256Digest::digest(self.key.verifying_key().as_bytes())
    }
}

impl ReceiptSigner for ReceiptAuthorityV1 {
    fn key_id(&self) -> &str {
        RECEIPT_KEY_ID
    }

    fn sign_execution_receipt(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        self.signer_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.key.sign(message).to_bytes())
    }
}

impl ReceiptKeyResolver for ReceiptAuthorityV1 {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        if key_id != RECEIPT_KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        let public_key = self.key.verifying_key().to_bytes();
        Ok(match self.trust {
            TrustStatusV1::Current => ReceiptVerificationKeyV1::current(public_key),
            TrustStatusV1::Historical => ReceiptVerificationKeyV1::historical(public_key),
        })
    }
}

struct FixedClockV1 {
    utc_ms: u64,
    monotonic_ms: u64,
    calls: AtomicUsize,
}

impl FixedClockV1 {
    fn new(utc_ms: u64, monotonic_ms: u64) -> Self {
        Self {
            utc_ms,
            monotonic_ms,
            calls: AtomicUsize::new(0),
        }
    }
}

impl AdapterClockV1 for FixedClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        AdapterClockObservationV1::Current(time_sample(
            10 + call as u64,
            self.utc_ms,
            self.monotonic_ms,
        ))
    }
}

struct UnavailableClockV1(AtomicUsize);

impl AdapterClockV1 for UnavailableClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        self.0.fetch_add(1, Ordering::Relaxed);
        AdapterClockObservationV1::Unavailable
    }
}

struct FixedEpochV1 {
    supervisor_epoch: u64,
    observer_generation: u64,
    utc_ms: u64,
    monotonic_ms: u64,
    calls: AtomicUsize,
}

impl FixedEpochV1 {
    fn new(
        supervisor_epoch: u64,
        observer_generation: u64,
        utc_ms: u64,
        monotonic_ms: u64,
    ) -> Self {
        Self {
            supervisor_epoch,
            observer_generation,
            utc_ms,
            monotonic_ms,
            calls: AtomicUsize::new(0),
        }
    }
}

impl SupervisorEpochObserverV1 for FixedEpochV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        self.calls.fetch_add(1, Ordering::Relaxed);
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            SafeU64::new(self.supervisor_epoch).unwrap(),
            Generation::new(self.observer_generation).unwrap(),
            time_sample(20, self.utc_ms, self.monotonic_ms),
        ))
    }
}

struct FixedAdmissionV1 {
    observation: AdapterConsumptionAdmissionObservationV1,
    calls: AtomicUsize,
}

impl FixedAdmissionV1 {
    fn new(observation: AdapterConsumptionAdmissionObservationV1) -> Self {
        Self {
            observation,
            calls: AtomicUsize::new(0),
        }
    }
}

impl AdapterConsumptionAdmissionObserverV1 for FixedAdmissionV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.observation
    }
}

struct CountingEntropyV1(AtomicUsize);

impl CountingEntropyV1 {
    fn new() -> Self {
        Self(AtomicUsize::new(0))
    }
}

impl AdapterReceiptEntropyV1 for CountingEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        assert_eq!(domain, AdapterReceiptEntropyDomainV1::ReceiptIdentity);
        let call = self.0.fetch_add(1, Ordering::Relaxed);
        destination.fill(0x80_u8.wrapping_add(call as u8));
        Ok(())
    }
}

#[test]
fn one_terminal_writer_signs_once_and_all_contenders_get_the_exact_receipt() {
    let root = TemporaryRootV1::new("contention");
    let identity = root_identity();
    let store = Arc::new(initialize_store(&root, identity));
    let initial = receive_fixture(&store);
    let current_grant = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let profile = signing_profile(&signer);
    let clock = FixedClockV1::new(1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();

    let mut handles = vec![initial];
    for _ in 1..16 {
        let AdapterInboxReadbackOutcomeV1::Received(received) = store
            .readback_grant_v1(grant_id(), &current_grant, &signer)
            .expect("RECEIVED readback succeeds")
        else {
            panic!("pre-terminal readback must return a consumable received handle");
        };
        handles.push(received);
    }
    // Give every contender a separately opened SQLite connection. This bypasses the
    // in-process store mutex and proves the immediate transaction is the signer lock.
    let mut contender_stores = vec![Arc::clone(&store)];
    for _ in 1..handles.len() {
        contender_stores.push(Arc::new(reopen_store(&root, identity)));
    }
    let barrier = Arc::new(Barrier::new(handles.len()));
    let results = std::thread::scope(|scope| {
        let mut joins = Vec::new();
        for (handle, store) in handles.into_iter().zip(contender_stores) {
            let barrier = Arc::clone(&barrier);
            let current_grant = &current_grant;
            let signer = &signer;
            let profile = &profile;
            let clock = &clock;
            let epoch = &epoch;
            let admission = &admission;
            let entropy = &entropy;
            joins.push(scope.spawn(move || {
                barrier.wait();
                let outcome = store
                    .consume_received_v1(
                        handle,
                        current_grant,
                        clock,
                        epoch,
                        admission,
                        entropy,
                        profile,
                        signer,
                        signer,
                    )
                    .expect("terminal contender succeeds");
                match outcome {
                    AdapterInboxConsumeOutcomeV1::Consumed(receipt) => {
                        (true, receipt.canonical_receipt().to_vec())
                    }
                    AdapterInboxConsumeOutcomeV1::RetainedReceipt(receipt) => {
                        (false, receipt.canonical_receipt().to_vec())
                    }
                    other => panic!("unexpected terminal contender outcome: {other:?}"),
                }
            }));
        }
        joins
            .into_iter()
            .map(|join| join.join().expect("terminal contender does not panic"))
            .collect::<Vec<_>>()
    });

    assert_eq!(results.iter().filter(|(won, _)| *won).count(), 1);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 1);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 1);
    assert_eq!(clock.calls.load(Ordering::Relaxed), 1);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 1);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 1);
    let exact_receipt = results[0].1.clone();
    assert!(results.iter().all(|(_, receipt)| *receipt == exact_receipt));

    drop(store);
    let reopened = reopen_store(&root, identity);
    let historical_grant = FixtureGrantResolverV1(TrustStatusV1::Historical);
    let historical_receipt = signer.historical_verifier();
    let AdapterInboxReadbackOutcomeV1::RetainedReceipt(readback) = reopened
        .readback_grant_v1(grant_id(), &historical_grant, &historical_receipt)
        .expect("historically verified receipt readback survives restart")
    else {
        panic!("terminal restart readback must return retained receipt");
    };
    assert_eq!(readback.canonical_receipt(), exact_receipt);
    assert_eq!(
        readback.decision(),
        AdapterRetainedReceiptDecisionV1::Consumed
    );
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn exactly_three_post_received_refusals_sign_atomically_and_survive_restart() {
    let cases = [
        (
            "expired",
            15,
            6_000_u64,
            AdapterConsumptionAdmissionObservationV1::Running,
            helix_dispatch_contracts::ExecutionReceiptRefusalCodeV1::GrantExpired,
        ),
        (
            "epoch",
            16,
            1_201_u64,
            AdapterConsumptionAdmissionObservationV1::Running,
            helix_dispatch_contracts::ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch,
        ),
        (
            "paused",
            15,
            1_201_u64,
            AdapterConsumptionAdmissionObservationV1::Paused,
            helix_dispatch_contracts::ExecutionReceiptRefusalCodeV1::AdapterPaused,
        ),
    ];
    for (label, terminal_epoch, terminal_monotonic, admission_state, expected_code) in cases {
        let root = TemporaryRootV1::new(label);
        let identity = root_identity();
        let store = initialize_store(&root, identity);
        let received = receive_fixture(&store);
        let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
        let signer = ReceiptAuthorityV1::current();
        let profile = signing_profile(&signer);
        let clock = FixedClockV1::new(1_005_000, terminal_monotonic.saturating_sub(1));
        let epoch = FixedEpochV1::new(terminal_epoch, 3, 1_005_001, terminal_monotonic);
        let admission = FixedAdmissionV1::new(admission_state);
        let entropy = CountingEntropyV1::new();
        let AdapterInboxConsumeOutcomeV1::DefinitelyRefused(receipt) = store
            .consume_received_v1(
                received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .expect("post-received refusal commits")
        else {
            panic!("{label} must produce one definite refusal");
        };
        assert_eq!(receipt.refusal_code(), Some(expected_code));
        assert_eq!(receipt.receipt_generation(), 3);
        let exact_receipt = receipt.canonical_receipt().to_vec();
        assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 1);
        drop(store);

        let reopened = reopen_store(&root, identity);
        let historical_grant = FixtureGrantResolverV1(TrustStatusV1::Historical);
        let historical_receipt = signer.historical_verifier();
        let AdapterInboxReadbackOutcomeV1::RetainedReceipt(readback) = reopened
            .readback_grant_v1(grant_id(), &historical_grant, &historical_receipt)
            .expect("refusal readback survives restart")
        else {
            panic!("{label} restart must recover its exact refusal");
        };
        assert_eq!(readback.canonical_receipt(), exact_receipt);
        assert_eq!(readback.refusal_code(), Some(expected_code));
    }
}

#[test]
fn unavailable_second_clock_retains_received_and_calls_no_epoch_pause_entropy_or_signer() {
    let root = TemporaryRootV1::new("unavailable-clock");
    let identity = root_identity();
    let store = initialize_store(&root, identity);
    let received = receive_fixture(&store);
    let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let profile = signing_profile(&signer);
    let clock = UnavailableClockV1(AtomicUsize::new(0));
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();
    assert_eq!(
        store
            .consume_received_v1(
                received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::ClockUnavailable
    );
    assert_eq!(clock.0.load(Ordering::Relaxed), 1);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 0);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 0);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        store
            .readback_grant_v1(grant_id(), &grant_resolver, &signer)
            .expect("failed terminal attempt remains readable"),
        AdapterInboxReadbackOutcomeV1::Received(_)
    ));
}

#[test]
fn active_global_corruption_fence_refuses_existing_receive_consume_and_strict_reopen() {
    let root = TemporaryRootV1::new("global-corruption-fence");
    let identity = root_identity();
    let store = initialize_store(&root, identity);
    let received = receive_fixture(&store);
    retain_global_corruption_fence_v1(root.path());

    let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let profile = signing_profile(&signer);
    let clock = FixedClockV1::new(1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();
    assert_eq!(
        store
            .consume_received_v1(
                received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::InvariantFailed
    );
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 0);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 0);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 0);

    let receive_clock = FixedClockV1::new(1_000_210, 1_210);
    let receive_epoch = FixedEpochV1::new(15, 4, 1_000_211, 1_211);
    assert_eq!(
        store
            .receive_grant_v1(
                &canonical_fixture_grant(),
                &grant_resolver,
                &receive_clock,
                &receive_epoch,
            )
            .unwrap_err(),
        AdapterInboxReceiveErrorV1::InvariantFailed
    );
    assert_eq!(receive_clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(receive_epoch.calls.load(Ordering::Relaxed), 0);
    drop(store);

    let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        5_000,
    )
    .expect("fenced root remains provisioner-attested");
    assert!(matches!(
        SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile()),
        Err(helix_dispatch_inbox_sqlite::AdapterInboxStoreOpenErrorV1::InvariantFailed)
    ));
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn real_scanner_fences_the_observed_branch_for_existing_handles_and_reopen() {
    let trusted_root = TemporaryRootV1::new("scanner-trusted");
    let observed_root = TemporaryRootV1::new("scanner-observed");
    let custody_root = TemporaryRootV1::new("scanner-custody");
    let identity = root_identity();

    let trusted_store = initialize_store(&trusted_root, identity);
    drop(receive_fixture(&trusted_store));
    drop(trusted_store);
    let observed_store = initialize_store(&observed_root, identity);
    let received = receive_fixture(&observed_store);
    drop(initialize_store(&custody_root, identity));

    let trusted_database = trusted_root.path().join("dispatch-inbox.sqlite3");
    let observed_database = observed_root.path().join("dispatch-inbox.sqlite3");
    let custody_database = custody_root.path().join("dispatch-inbox.sqlite3");
    let trusted_connection = open_adapter_database_for_scanner_v1(&trusted_database);
    let mut observed_connection = open_adapter_database_for_scanner_v1(&observed_database);
    let mut custody_connection = open_adapter_database_for_scanner_v1(&custody_database);
    let grant = load_counterpart_grant_projection_v1(&trusted_connection);
    let trusted_counterpart = CounterpartProjectionV1::new("scanner-peer-trusted", Some(&grant));
    let observed_counterpart = CounterpartProjectionV1::new("scanner-peer-observed", None);
    let trusted_counterpart_connection = trusted_counterpart.open();
    let mut observed_counterpart_connection = observed_counterpart.open();
    let ids = AdapterCrossStoreIdsForTestV1::try_new(
        grant.grant_id,
        grant.operation_id.clone(),
        grant.dispatch_attempt_id,
        None,
    )
    .expect("scanner selection identities are bounded");

    let first = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect("real scanner retains observed fence and separate custody");
    let repeat = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect("real scanner retry reuses both retained records");
    let AdapterHistoryCustodyForTestV1::Quarantined(first) = first else {
        panic!("missing peer grant must classify as corruption");
    };
    let AdapterHistoryCustodyForTestV1::Quarantined(repeat) = repeat else {
        panic!("scanner retry must remain corrupt");
    };
    assert_eq!(first.reason_code(), "ORPHAN_ADAPTER_INBOX");
    assert_eq!(repeat.reason_code(), first.reason_code());
    assert_eq!(
        repeat.quarantine_generation(),
        first.quarantine_generation(),
        "separate custody retry is idempotent"
    );

    let local_fence = read_global_fence_projection_v1(&observed_connection);
    let separate_custody = read_global_fence_projection_v1(&custody_connection);
    assert_eq!(local_fence.quarantine_id, separate_custody.quarantine_id);
    assert_eq!(
        local_fence.evidence_digest,
        separate_custody.evidence_digest
    );
    assert_eq!(local_fence.reason_code, separate_custody.reason_code);
    assert_eq!(local_fence.resolved_generation, None);
    assert_eq!(separate_custody.resolved_generation, None);

    let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let profile = signing_profile(&signer);
    let clock = FixedClockV1::new(1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();
    assert_eq!(
        observed_store
            .consume_received_v1(
                received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::InvariantFailed
    );
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 0);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 0);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 0);

    assert_eq!(
        observed_connection
            .execute(
                "UPDATE inbox_quarantines
                 SET resolved_generation = quarantine_generation + 1
                 WHERE quarantine_id = ?1",
                [local_fence.quarantine_id.as_slice()],
            )
            .expect("local fence resolution projection updates once"),
        1
    );
    let after_resolution = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect("resolved local projection still reuses permanent custody");
    let AdapterHistoryCustodyForTestV1::Quarantined(after_resolution) = after_resolution else {
        panic!("resolved source incident must remain fenced");
    };
    assert_eq!(after_resolution.reason_code(), first.reason_code());
    assert_eq!(
        after_resolution.quarantine_generation(),
        first.quarantine_generation()
    );
    let receive_clock = FixedClockV1::new(1_000_210, 1_210);
    let receive_epoch = FixedEpochV1::new(15, 4, 1_000_211, 1_211);
    assert_eq!(
        observed_store
            .receive_grant_v1(
                &canonical_fixture_grant(),
                &grant_resolver,
                &receive_clock,
                &receive_epoch,
            )
            .unwrap_err(),
        AdapterInboxReceiveErrorV1::InvariantFailed,
        "resolved incident remains a permanent source-branch fence"
    );
    assert_eq!(receive_clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(receive_epoch.calls.load(Ordering::Relaxed), 0);
    drop(observed_store);

    for root in [&observed_root, &custody_root] {
        let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
            root.path().to_path_buf(),
            identity,
            5_000,
        )
        .expect("fenced root remains provisioner-attested");
        assert!(matches!(
            SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile()),
            Err(helix_dispatch_inbox_sqlite::AdapterInboxStoreOpenErrorV1::InvariantFailed)
        ));
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn scanner_holds_the_observed_writer_lock_from_capture_through_local_fence() {
    let trusted_root = TemporaryRootV1::new("scanner-lock-trusted");
    let observed_root = TemporaryRootV1::new("scanner-lock-observed");
    let custody_root = TemporaryRootV1::new("scanner-lock-custody");
    let identity = root_identity();
    let trusted_store = initialize_store_with_busy_wait(&trusted_root, identity, 25);
    drop(receive_fixture(&trusted_store));
    drop(trusted_store);
    let observed_store = initialize_store_with_busy_wait(&observed_root, identity, 25);
    let racing_received = receive_fixture(&observed_store);
    drop(initialize_store_with_busy_wait(&custody_root, identity, 25));

    let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let AdapterInboxReadbackOutcomeV1::Received(post_fence_received) = observed_store
        .readback_grant_v1(grant_id(), &grant_resolver, &signer)
        .expect("second received handle is recovered before the scan")
    else {
        panic!("pre-scan readback must remain RECEIVED");
    };

    let trusted_database = trusted_root.path().join("dispatch-inbox.sqlite3");
    let observed_database = observed_root.path().join("dispatch-inbox.sqlite3");
    let custody_database = custody_root.path().join("dispatch-inbox.sqlite3");
    let trusted_connection = open_adapter_database_for_scanner_v1(&trusted_database);
    let mut observed_connection = open_adapter_database_for_scanner_v1(&observed_database);
    let mut custody_connection = open_adapter_database_for_scanner_v1(&custody_database);
    let grant = load_counterpart_grant_projection_v1(&trusted_connection);
    let trusted_counterpart =
        CounterpartProjectionV1::new("scanner-lock-peer-trusted", Some(&grant));
    let observed_counterpart = CounterpartProjectionV1::new("scanner-lock-peer-observed", None);
    let trusted_counterpart_connection = trusted_counterpart.open();
    trusted_counterpart_connection
        .busy_timeout(Duration::from_secs(10))
        .expect("scanner peer receives a bounded wait");
    let mut observed_counterpart_connection = observed_counterpart.open();
    let ids = AdapterCrossStoreIdsForTestV1::try_new(
        grant.grant_id,
        grant.operation_id,
        grant.dispatch_attempt_id,
        None,
    )
    .expect("scanner lock selection identities are bounded");

    let blocker = trusted_counterpart.open();
    blocker
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("counterpart read blocker begins");
    let scanner = std::thread::spawn(move || {
        classify_and_retain_adapter_connections_for_test_v1(
            &trusted_connection,
            &mut observed_connection,
            &trusted_counterpart_connection,
            &mut observed_counterpart_connection,
            &mut custody_connection,
            &ids,
            AdapterLifecycleRelationshipForTestV1::AdapterReceived,
        )
    });

    std::thread::sleep(Duration::from_millis(100));
    let mut probe = Connection::open(&observed_database).expect("observed lock probe opens");
    probe
        .busy_timeout(Duration::ZERO)
        .expect("observed lock probe never waits");
    let before_generation = probe
        .query_row(
            "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("pre-fence generation reads");
    let mut scanner_writer_lock_observed = false;
    for _ in 0..200 {
        match probe.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(transaction) => {
                transaction.rollback().expect("lock probe rolls back");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                scanner_writer_lock_observed = true;
                break;
            }
            Err(error) => panic!("unexpected observed lock probe failure: {error:?}"),
        }
    }
    assert!(
        scanner_writer_lock_observed,
        "scanner must lock observed before it blocks on counterpart capture; finished={}",
        scanner.is_finished()
    );

    let profile = signing_profile(&signer);
    let clock = FixedClockV1::new(1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();
    assert_eq!(
        observed_store
            .consume_received_v1(
                racing_received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::StoreBusy,
        "existing handle cannot write while the scan cut is being classified"
    );
    assert_eq!(
        probe
            .query_row(
                "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("generation remains readable during WAL writer lock"),
        before_generation,
        "no activation commits before the local fence"
    );
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 0);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 0);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 0);

    blocker
        .execute_batch("ROLLBACK")
        .expect("counterpart read blocker releases");
    let outcome = scanner
        .join()
        .expect("scanner thread does not panic")
        .expect("scanner completes after counterpart release");
    assert!(matches!(
        outcome,
        AdapterHistoryCustodyForTestV1::Quarantined(_)
    ));
    assert_eq!(
        observed_store
            .consume_received_v1(
                post_fence_received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &signer,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::InvariantFailed,
        "the committed source fence permanently replaces transient writer exclusion"
    );
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(epoch.calls.load(Ordering::Relaxed), 0);
    assert_eq!(admission.calls.load(Ordering::Relaxed), 0);
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn scanner_freezes_counterpart_before_adapter_and_releases_it_only_after_local_fence() {
    let trusted_root = TemporaryRootV1::new("scanner-double-cut-trusted");
    let observed_root = TemporaryRootV1::new("scanner-double-cut-observed");
    let custody_root = TemporaryRootV1::new("scanner-double-cut-custody");
    let identity = root_identity();
    let trusted_store = initialize_store_with_busy_wait(&trusted_root, identity, 25);
    drop(receive_fixture(&trusted_store));
    drop(trusted_store);
    let observed_store = initialize_store_with_busy_wait(&observed_root, identity, 25);
    drop(receive_fixture(&observed_store));
    drop(observed_store);
    drop(initialize_store_with_busy_wait(&custody_root, identity, 25));

    let trusted_database = trusted_root.path().join("dispatch-inbox.sqlite3");
    let observed_database = observed_root.path().join("dispatch-inbox.sqlite3");
    let custody_database = custody_root.path().join("dispatch-inbox.sqlite3");
    let trusted_connection = open_adapter_database_for_scanner_v1(&trusted_database);
    let mut observed_connection = open_adapter_database_for_scanner_v1(&observed_database);
    observed_connection
        .busy_timeout(Duration::from_secs(10))
        .expect("double-cut scanner receives a bounded adapter wait");
    let mut custody_connection = open_adapter_database_for_scanner_v1(&custody_database);
    let grant = load_counterpart_grant_projection_v1(&trusted_connection);
    let trusted_counterpart =
        CounterpartProjectionV1::new("scanner-double-cut-peer-trusted", Some(&grant));
    let observed_counterpart =
        CounterpartProjectionV1::new("scanner-double-cut-peer-observed", None);
    let trusted_counterpart_connection = trusted_counterpart.open();
    let mut observed_counterpart_connection = observed_counterpart.open();
    observed_counterpart_connection
        .busy_timeout(Duration::from_secs(10))
        .expect("double-cut scanner receives a bounded counterpart wait");
    let ids = AdapterCrossStoreIdsForTestV1::try_new(
        grant.grant_id,
        grant.operation_id,
        grant.dispatch_attempt_id,
        None,
    )
    .expect("double-cut selection identities are bounded");

    let adapter_blocker = Connection::open(&observed_database).expect("adapter blocker opens");
    adapter_blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("adapter blocker owns the writer before scanner start");
    let mut counterpart_probe = observed_counterpart.open();
    counterpart_probe
        .busy_timeout(Duration::ZERO)
        .expect("counterpart cut probe never waits");

    let scanner = std::thread::spawn(move || {
        classify_and_retain_adapter_connections_for_test_v1(
            &trusted_connection,
            &mut observed_connection,
            &trusted_counterpart_connection,
            &mut observed_counterpart_connection,
            &mut custody_connection,
            &ids,
            AdapterLifecycleRelationshipForTestV1::AdapterReceived,
        )
    });

    let counterpart_locked_first = (0..200).any(|_| {
        match counterpart_probe.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        {
            Ok(transaction) => {
                transaction
                    .rollback()
                    .expect("counterpart probe rolls back");
                std::thread::sleep(Duration::from_millis(10));
                false
            }
            Err(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                true
            }
            Err(error) => panic!("unexpected counterpart cut probe failure: {error:?}"),
        }
    });
    assert!(
        counterpart_locked_first && !scanner.is_finished(),
        "scanner must freeze coordinator counterpart before it can obtain the adapter cut"
    );

    adapter_blocker
        .execute_batch("ROLLBACK")
        .expect("adapter blocker releases the second cut");
    let counterpart_released = (0..500).any(|_| {
        match counterpart_probe.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        {
            Ok(transaction) => {
                transaction
                    .rollback()
                    .expect("released counterpart probe rolls back");
                true
            }
            Err(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                std::thread::sleep(Duration::from_millis(10));
                false
            }
            Err(error) => panic!("unexpected counterpart release probe failure: {error:?}"),
        }
    });
    assert!(counterpart_released, "scanner releases the counterpart cut");
    let local_probe = Connection::open(&observed_database).expect("local fence probe opens");
    assert_eq!(
        local_probe
            .query_row(
                "SELECT COUNT(*) FROM inbox_quarantines WHERE grant_id IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("local fence is visible when counterpart cut releases"),
        1,
        "counterpart cut cannot release before the adapter fence commits"
    );
    assert!(matches!(
        scanner
            .join()
            .expect("double-cut scanner does not panic")
            .expect("double-cut scanner completes"),
        AdapterHistoryCustodyForTestV1::Quarantined(_)
    ));
}

fn retain_global_corruption_fence_v1(root: &Path) {
    let mut connection =
        Connection::open(root.join("dispatch-inbox.sqlite3")).expect("adapter database opens raw");
    let transaction = connection
        .transaction()
        .expect("global corruption transaction begins");
    let store_generation: i64 = transaction
        .query_row(
            "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("store generation reads");
    let generation = store_generation + 1;
    transaction
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = ?1, quarantine_generation = ?1
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
               AND store_generation = ?2",
            params![generation, store_generation],
        )
        .expect("global corruption generation advances");
    transaction
        .execute(
            "INSERT INTO inbox_quarantines (
                quarantine_id, grant_id, evidence_digest, public_reason_code,
                quarantine_generation, resolved_generation
             ) VALUES (?1, NULL, ?2, 'CROSS_STORE_DISAGREEMENT', ?3, NULL)",
            params![
                [0x91_u8; 32].as_slice(),
                [0x92_u8; 32].as_slice(),
                generation
            ],
        )
        .expect("global corruption custody inserts");
    transaction
        .commit()
        .expect("global corruption custody commits");
}

#[cfg(feature = "test-fault-injection")]
struct CounterpartGrantProjectionV1 {
    grant_id: [u8; 32],
    operation_id: String,
    dispatch_attempt_id: [u8; 32],
    grant_digest: [u8; 32],
}

#[cfg(feature = "test-fault-injection")]
struct CounterpartProjectionV1(PathBuf);

#[cfg(feature = "test-fault-injection")]
impl CounterpartProjectionV1 {
    fn new(label: &str, grant: Option<&CounterpartGrantProjectionV1>) -> Self {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-t097-live-counterpart-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        let connection = Connection::open(&path).expect("counterpart projection file creates");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE dispatch_grants (
                    grant_id BLOB NOT NULL,
                    operation_id TEXT COLLATE BINARY NOT NULL,
                    dispatch_attempt_id BLOB NOT NULL,
                    grant_digest BLOB NOT NULL,
                    created_generation INTEGER NOT NULL DEFAULT 1,
                    preparation_transition_generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (grant_id),
                    UNIQUE (grant_id, operation_id, dispatch_attempt_id)
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE dispatch_receipts (
                    receipt_id BLOB NOT NULL,
                    grant_id BLOB NOT NULL,
                    operation_id TEXT COLLATE BINARY NOT NULL,
                    dispatch_attempt_id BLOB NOT NULL,
                    receipt_digest BLOB NOT NULL,
                    receipt_generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (receipt_id),
                    FOREIGN KEY (grant_id, operation_id, dispatch_attempt_id)
                        REFERENCES dispatch_grants (
                            grant_id, operation_id, dispatch_attempt_id
                        )
                 ) STRICT, WITHOUT ROWID;",
            )
            .expect("counterpart projection schema initializes");
        if let Some(grant) = grant {
            connection
                .execute(
                    "INSERT INTO dispatch_grants (
                        grant_id, operation_id, dispatch_attempt_id, grant_digest
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        grant.grant_id.as_slice(),
                        grant.operation_id,
                        grant.dispatch_attempt_id.as_slice(),
                        grant.grant_digest.as_slice(),
                    ],
                )
                .expect("counterpart grant inserts");
        }
        drop(connection);
        Self(path)
    }

    fn open(&self) -> Connection {
        let connection = Connection::open(&self.0).expect("counterpart projection opens");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("counterpart foreign keys enable");
        connection
    }
}

#[cfg(feature = "test-fault-injection")]
impl Drop for CounterpartProjectionV1 {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

#[cfg(feature = "test-fault-injection")]
fn open_adapter_database_for_scanner_v1(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("adapter scanner connection opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("adapter scanner foreign keys enable");
    connection
}

#[cfg(feature = "test-fault-injection")]
fn load_counterpart_grant_projection_v1(connection: &Connection) -> CounterpartGrantProjectionV1 {
    let (grant_id, operation_id, dispatch_attempt_id, grant_digest): (
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT grant_id, operation_id, dispatch_attempt_id, grant_digest
             FROM grant_inbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("received grant projection reads");
    CounterpartGrantProjectionV1 {
        grant_id: grant_id.try_into().expect("grant id remains 32 bytes"),
        operation_id,
        dispatch_attempt_id: dispatch_attempt_id
            .try_into()
            .expect("dispatch attempt id remains 32 bytes"),
        grant_digest: grant_digest
            .try_into()
            .expect("grant digest remains 32 bytes"),
    }
}

#[cfg(feature = "test-fault-injection")]
struct GlobalFenceProjectionV1 {
    quarantine_id: Vec<u8>,
    evidence_digest: Vec<u8>,
    reason_code: String,
    resolved_generation: Option<i64>,
}

#[cfg(feature = "test-fault-injection")]
fn read_global_fence_projection_v1(connection: &Connection) -> GlobalFenceProjectionV1 {
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM inbox_quarantines WHERE grant_id IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("global fence count reads"),
        1
    );
    connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code, resolved_generation
             FROM inbox_quarantines WHERE grant_id IS NULL",
            [],
            |row| {
                Ok(GlobalFenceProjectionV1 {
                    quarantine_id: row.get(0)?,
                    evidence_digest: row.get(1)?,
                    reason_code: row.get(2)?,
                    resolved_generation: row.get(3)?,
                })
            },
        )
        .expect("global fence projection reads")
}

#[test]
fn historical_new_receipt_verifier_rolls_back_every_generation_and_retains_received() {
    let root = TemporaryRootV1::new("historical-new-receipt");
    let identity = root_identity();
    let store = initialize_store(&root, identity);
    let received = receive_fixture(&store);
    let grant_resolver = FixtureGrantResolverV1(TrustStatusV1::Current);
    let signer = ReceiptAuthorityV1::current();
    let historical_verifier = signer.historical_verifier();
    let profile = signing_profile(&signer);
    let clock = FixedClockV1::new(1_000_200, 1_200);
    let epoch = FixedEpochV1::new(15, 3, 1_000_201, 1_201);
    let admission = FixedAdmissionV1::new(AdapterConsumptionAdmissionObservationV1::Running);
    let entropy = CountingEntropyV1::new();
    assert_eq!(
        store
            .consume_received_v1(
                received,
                &grant_resolver,
                &clock,
                &epoch,
                &admission,
                &entropy,
                &profile,
                &signer,
                &historical_verifier,
            )
            .unwrap_err(),
        AdapterInboxConsumeErrorV1::ReceiptVerificationFailed
    );
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 1);
    let AdapterInboxReadbackOutcomeV1::Received(recovered) = store
        .readback_grant_v1(grant_id(), &grant_resolver, &signer)
        .expect("verification failure leaves RECEIVED durable")
    else {
        panic!("failed verification must not retain a partial receipt");
    };

    let current_clock = FixedClockV1::new(1_000_210, 1_210);
    let current_epoch = FixedEpochV1::new(15, 3, 1_000_211, 1_211);
    let AdapterInboxConsumeOutcomeV1::Consumed(receipt) = store
        .consume_received_v1(
            recovered,
            &grant_resolver,
            &current_clock,
            &current_epoch,
            &admission,
            &entropy,
            &profile,
            &signer,
            &signer,
        )
        .expect("current verification retries the still-received row")
    else {
        panic!("retry with current verifier must consume");
    };
    assert_eq!(receipt.receipt_generation(), 3);
    assert_eq!(signer.signer_calls.load(Ordering::Relaxed), 2);
}

fn receive_fixture(
    store: &SqliteDispatchInboxStoreV1,
) -> helix_dispatch_inbox_sqlite::ReceivedInboxGrantV1 {
    let clock = FixedClockV1::new(1_000_100, 1_100);
    let epoch = FixedEpochV1::new(15, 2, 1_000_101, 1_101);
    let AdapterInboxReceiveOutcomeV1::Received(received) = store
        .receive_grant_v1(
            &canonical_fixture_grant(),
            &FixtureGrantResolverV1(TrustStatusV1::Current),
            &clock,
            &epoch,
        )
        .expect("fixture grant reaches RECEIVED")
    else {
        panic!("fixture grant must be first durable receive");
    };
    received
}

fn initialize_store(
    root: &TemporaryRootV1,
    identity: AdapterInboxRootIdentityEvidenceV1,
) -> SqliteDispatchInboxStoreV1 {
    initialize_store_with_busy_wait(root, identity, 5_000)
}

fn initialize_store_with_busy_wait(
    root: &TemporaryRootV1,
    identity: AdapterInboxRootIdentityEvidenceV1,
    maximum_busy_wait_ms: u64,
) -> SqliteDispatchInboxStoreV1 {
    let config = AdapterInboxStoreConfigV1::try_new_empty_attested(
        root.path().to_path_buf(),
        identity,
        maximum_busy_wait_ms,
    )
    .expect("empty adapter root is provisioner-attested");
    SqliteDispatchInboxStoreV1::initialize_empty_v1(
        config,
        AdapterInboxInitializationV1::try_new(15, 1, RECEIPT_PROFILE_DIGEST)
            .expect("initial metadata is bounded"),
        adapter_profile(),
    )
    .expect("adapter store initializes")
}

fn reopen_store(
    root: &TemporaryRootV1,
    identity: AdapterInboxRootIdentityEvidenceV1,
) -> SqliteDispatchInboxStoreV1 {
    let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        5_000,
    )
    .expect("existing adapter root remains provisioner-attested");
    SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile())
        .expect("terminal graph passes strict reopen verification")
}

fn adapter_profile() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        "adapter-v1",
        1,
        Sha256Digest::parse_hex(CAPABILITY_DIGEST).unwrap(),
    )
    .unwrap()
}

fn signing_profile(authority: &ReceiptAuthorityV1) -> AdapterReceiptSigningProfileV1 {
    AdapterReceiptSigningProfileV1::try_new(
        RECEIPT_KEY_ID,
        authority.fingerprint(),
        Sha256Digest::from_bytes(RECEIPT_PROFILE_DIGEST),
    )
    .unwrap()
}

fn canonical_fixture_grant() -> Vec<u8> {
    let corpus: serde_json::Value = serde_json::from_str(CASES).unwrap();
    serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap()
}

fn grant_id() -> Sha256Digest {
    Sha256Digest::parse_hex(GRANT_ID).unwrap()
}

fn root_identity() -> AdapterInboxRootIdentityEvidenceV1 {
    AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x41; 32])
}

fn time_sample(clock_generation: u64, utc_ms: u64, monotonic_ms: u64) -> AdapterTimeSampleV1 {
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
            "helix-t049-t050-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary adapter root creates");
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
