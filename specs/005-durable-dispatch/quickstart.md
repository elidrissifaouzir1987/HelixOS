# Quickstart: Validate Durable One-Shot Dispatch

This guide defines the evidence sequence for PLAN-005. Commands become runnable as the
corresponding tasks land. A pass proves a synthetic no-effect dispatch protocol; it does
not prove a host effect, physical power-loss durability, production supervisor/IPC,
full-machine restore or Tier 1.

## 1. Preconditions

- Work from the repository root on `codex/plan-005-durable-dispatch`.
- Rust/Cargo must resolve through `kernel/rust-toolchain.toml` (`1.96.1`).
- Use `--locked`; do not update unrelated dependencies.
- Preserve the merged pre-feature removal baseline
  `6f8dfdd5194792e8592cd10ebaaf8828833effbe`.
- Do not stage or rewrite the 27 unrelated local Rust formatting changes under
  `helixos-kernel`, `helixos-mcp-shim` and `helixos-provision`.
- Never place private signing keys, PATs, secrets, native user paths or sensitive
  canonical payloads in fixtures, Graphify memory or evidence.

## 2. Specification and contract gate

```sh
python3 -m json.tool specs/005-durable-dispatch/contracts/dispatch-backup-manifest-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/fault-boundaries-v1.json >/dev/null
rg -n "\[NEEDS CLARIFICATION:|\[FEATURE|\[DATE\]|\$ARGUMENTS" \
  specs/005-durable-dispatch --glob '!quickstart.md'
```

Expected:

- JSON schema parses;
- the `rg` command returns no unresolved template marker;
- `spec.md`, `research.md`, `data-model.md`, `plan.md` and every contract agree on the
  5,000 ms ceiling, `EXECUTING` meaning, no-token/no-effect boundary, receipt decisions,
  schema V2 overlay and restore nonclaims.

## 3. Fast workspace quality gate

```sh
cd kernel
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Expected: all existing PLAN-001 through PLAN-004 tests and PLAN-005 tests pass without
modifying golden bytes or frozen PLAN-004 fault registries.

## 4. Canonical grant and receipt corpus

```sh
cd kernel
cargo test --locked -p helix-dispatch-contracts --test grant_contract
cargo test --locked -p helix-dispatch-contracts --test receipt_contract
cargo test --locked -p helix-plan-dispatch --test contract
cargo run --locked -p helix-coordinator-sqlite --features test-fault-injection \
  --example durable_dispatch_corpus -- \
  ../contracts/fixtures/durable-dispatch-v1/cases.json \
  ../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json
```

Expected:

- identical canonical bytes/digests on all matrix hosts;
- 100% denial of tamper, wrong domain/purpose/key, stale epoch, deadline, cross-operation,
  cross-adapter, conflict, unknown field/version and oversized cases;
- no public debug/error output contains seeded restricted markers.

## 5. Coordinator-only authority boundary

```sh
cd kernel
cargo test --locked -p helix-plan-dispatch --test authority
cargo test --locked -p helix-coordinator-sqlite --test dispatch
cargo test --locked -p helix-coordinator-sqlite --test dispatch_contention
```

Expected:

- only lookup key plus expected plan/preparation bindings enter the public request;
- complete durable PLAN-004 state is reloaded and revalidated;
- compile/source contracts reject `PreparedOperationV1`, direct rows and legacy kernel
  authority as dispatch input;
- final comparison and signed bytes commit under the fixed-order guards/permit;
- exact capacity succeeds, over-by-one and deadline equality deny;
- 10,000 repetitions, 100 x 64-thread rounds and 20 x 8-process rounds retain one
  grant/operation/nonce; this coordinator-only gate is the first half of SC-001, whose
  full adapter-consumption matrix runs in section 7.

## 6. Schema V1-to-V2 migration and rollback refusal

```sh
cd kernel
cargo test --locked -p helix-coordinator-sqlite --test dispatch_migration
```

Expected:

- strict V1 opens only V1 and still rejects dispatch objects;
- ordinary V2 open does not auto-migrate;
- explicit migration requires PAUSE/quiescence and a verified V1 backup;
- V1 objects/rows and schema digest remain unchanged;
- the additive overlay/migration receipt and `user_version=2` commit together;
- uncertain migration is classified by exact readback, not rerun;
- V1 rejects V2 and in-place downgrade is refused after any grant history.

## 7. Adapter inbox one-shot behavior

```sh
cd kernel
cargo test --locked -p helix-dispatch-inbox-sqlite --test contract
cargo test --locked -p helix-dispatch-inbox-sqlite --test consume_once
cargo test --locked -p helix-dispatch-inbox-sqlite --test contention
cargo test --locked -p helix-dispatch-inbox-sqlite --test stale_epoch
cargo test --locked -p helix-coordinator-sqlite --test dispatch_end_to_end_contention
```

Expected:

- independent current supervisor epoch is mandatory;
- grant/operation/nonce are create-only unique;
- exact duplicate returns the retained state/receipt;
- conflict creates permanent evidence and zero consumption;
- receive commits before acceptance; consume/refuse plus exact receipt commit together;
- `REFUSED_DEFINITE` exists only post-`RECEIVED` and carries exactly
  `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` or `ADAPTER_PAUSED`;
- pre-`RECEIVED` `DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`,
  `CAPABILITY_MISMATCH` and `INBOX_CAPACITY_EXHAUSTED` retain durable redacted
  diagnostic/quarantine evidence, create no receipt and cannot alone release a hold;
- receipt signer domain/purpose is distinct from grant/plan;
- the complete SC-001 matrix of exactly 10,000 repeated requests, 100 x 64-thread rounds
  and 20 x 8-process rounds runs end to end and observes exactly one adapter consumption
  with zero duplicate consumptions;
- PLAN-005 exports no execution-token API.

## 8. Lost acknowledgement and definite absence

```sh
cd kernel
cargo test --locked -p helix-plan-dispatch --test ambiguity
cargo test --locked -p helix-coordinator-sqlite --test dispatch_readback
```

Expected:

- dropped receive and consume acknowledgements recover the original retained receipt;
- redelivery uses byte-identical grant and never renews the deadline;
- each possible-handoff attempt starts exactly one automatic readback sequence with at
  most four observations after 0/25/75/175 ms backoffs, at offsets 0/25/100/275 ms, and
  stops no later than 500 ms after the first observation or an earlier caller/grant
  deadline;
- a receipt retained before expiry remains verifiable after expiry only as evidence of
  its earlier decision and renews no authority;
- empty inbox alone never proves absence after possible handoff;
- readback exhaustion or unavailability yields `OUTCOME_UNKNOWN` and then explicit
  `RECONCILIATION_REQUIRED`, never definite absence or another automatic sequence;
- definite absence requires quiesced/fenced transport, matching healthy root/epoch,
  closed deadline and authoritative generation;
- unresolved possible handoff becomes `OUTCOME_UNKNOWN` with held budget/recovery and no
  replacement grant, then explicit `RECONCILIATION_REQUIRED` custody;
- exact signed no-consumption refusal alone closes through the full normative history to
  `FAILED` and releases the exact PLAN-004 hold once; late consumed evidence never jumps
  from reconciliation back to `EXECUTING`.

## 9. Closed fault and process-kill corpus

```sh
cd kernel
cargo test --locked -p helix-plan-dispatch --features test-fault-injection --test conformance
cargo test --locked -p helix-coordinator-sqlite --features test-fault-injection --test dispatch_faults
cargo test --locked -p helix-dispatch-inbox-sqlite --features test-fault-injection --test process_crash
```

Expected:

- `contracts/fault-boundaries-v1.json` provides one ordered versioned PLAN-005 registry
  of exactly 90 boundaries and 180 declared in-process/process-kill cases covering
  signing, guard/commit, handoff, receive,
  epoch, consume, receipt, acknowledgement, readback, migration and restore;
- every boundary is reached by in-process and applicable process-kill drivers;
- no boundary yields duplicate grant/consumption, false absence/success or late mutation;
- PLAN-004's 123-boundary/167-case registry remains unchanged.

## 10. Queue, flood and control lane

```sh
cd kernel
cargo test --locked -p helix-dispatch-inbox-sqlite --test queue_control
cargo test --locked -p helix-coordinator-sqlite --test dispatch_queue_control
```

Expected:

- ordinary capacity is exactly 1,024 and control capacity 32;
- at saturation and during a 10,000-request duplicate flood, ordinary work refuses or
  backpressures within 50 ms;
- PAUSE/status/reconciliation remain at p99 <= 100 ms across all 100 trials on the
  declared controlled profile;
- metrics remain bounded and payload-free.

## 11. Corruption, retention and redaction

```sh
cd kernel
cargo test --locked --all-features -p helix-coordinator-sqlite \
  --test dispatch_corruption -- --test-threads=1
cargo test --locked --all-features -p helix-dispatch-inbox-sqlite \
  --test corruption -- --test-threads=1
cargo test --locked -p helix-plan-dispatch --test redaction
```

Expected:

- missing/orphan/conflicting grant/receipt/transition/outbox rows, generation reuse,
  rollback and truncation fail closed;
- the exact retained checkpoint and all five clean lifecycle controls remain mutation-free,
  while a different fully strict checkpoint returns payload-free `CHECKPOINT_MISMATCH`
  without source fencing or external custody;
- authoritative rows and tombstones cannot be deleted/reused;
- no pruning or secure-erasure claim exists;
- canonical wires are restricted store data while public logs/debug/events redact
  internal IDs/digests and seeded secret/path markers.

## 12. Paused cross-store backup and clean restore

```sh
cd kernel
cargo test --locked --all-features -p helix-coordinator-sqlite \
  --test dispatch_restore -- --test-threads=1
cargo test --locked --all-features -p helix-dispatch-inbox-sqlite \
  --test backup_restore -- --test-threads=1
```

Expected:

- PAUSE/quiescence fences both domains before sequential online backups;
- coordinator/adapter manifests and signed top-level index bind roots, schema/database
  digests, generations, inventory and public verifier profiles;
- private signing keys are absent;
- empty restored roots use new identities/epochs, `RESTORE_PENDING` and PAUSED;
- zero old grants are redelivered/reactivated and possible acceptance is quarantined;
- evidence is labelled subsystem-only, not full-machine/Tier 1.

## 13. Portability matrix

The same workflow commands run unchanged on:

- `ubuntu-24.04` x86_64;
- `macos-26` arm64;
- `windows-2022` x64.

Each job first asserts its actual OS/architecture, runs PLAN-001 through PLAN-004
prerequisites, then PLAN-005. Platform capability refusal belongs in fixtures; tests do
not silently branch/skip by OS. Line-sensitive JSON/SQL/fixture artifacts are LF-pinned.

## 14. Physical M4 benchmark

```sh
cd kernel
cargo run --locked --release -p helix-coordinator-sqlite \
  --example durable_dispatch_benchmark --features controlled-benchmark -- \
  --warmups 500 --samples 10000 --output ../specs/005-durable-dispatch/evidence/m4-raw.json
```

Measurement starts at final retained guard entry and ends after coordinator verification
of the exact consumed receipt. Evidence records hardware model/RAM, macOS, filesystem /
SQLite profile, toolchain, source/lock/schema digests, queue depth, corpus, concurrency,
raw samples and p50/p95/p99. Required: p95 <= 50 ms, p99 <= 100 ms. A hosted or local
result without exact declared metadata remains diagnostic and cannot satisfy the gate.

## 15. Supply chain and isolated removal

```sh
python3 tools/plan005_supply_chain.py build --repository . --output /tmp/plan005-supply
python3 tools/plan005_supply_chain.py verify --repository . --output /tmp/plan005-supply
python3 tools/plan005_removal_drill.py --repository . --baseline 6f8dfdd5194792e8592cd10ebaaf8828833effbe
```

Without `--source-commit`, the removal command is an explicitly diagnostic snapshot of
the current filtered working tree: it ignores the 27 recorded user-owned Rust changes
and cannot satisfy immutable release evidence. For the release gate, run the committed
driver and manifest from the exact checkout and add
`--source-commit "$(git rev-parse HEAD)"`; the driver refuses a different `HEAD`, local
tooling bytes that differ from that commit, a pre-existing Cargo target, or any output
classified as immutable evidence when tests were skipped.

Expected:

- complete dependency closure/adjacency, exact lock, bundled SQLite source/features,
  licenses, RustSec/SPDX revisions, SBOM/provenance and semantic tamper tests pass;
- secret/private-path scans pass;
- removal deletes only PLAN-005 surfaces, restores the pre-feature lock/schema
  integration and byte-verifies protected PLAN-001 through PLAN-004 and legacy files;
- all prerequisite tests remain green.

## 16. Roadmap and immutable release evidence

```sh
python3 tools/update_roadmap.py --check
```

`conformance/catalog.yaml` must contain PLAN-005 acceptance IDs, exact evidence URIs and
`claim_status: pending-evidence`. GitHub accepts `workflow_dispatch` only after the
workflow file exists on the default branch. For this new-workflow bootstrap, retain the
first exact successful `push` run from `codex/plan-005-durable-dispatch`; the unchanged
manual event becomes available after merge. Record Linux/macOS/Windows/release artifact
IDs, upload digests, expiries, attestations, Rekor records and strict constrained
verification. Do not promote hosted synthetic evidence to physical M4, power-loss,
production or Tier 1 proof.
