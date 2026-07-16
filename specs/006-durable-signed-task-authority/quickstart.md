# Quickstart: Validate Durable Signed Task Authority

This guide defines the post-implementation validation path for PLAN-006. Until the four
PLAN-006 crates, tests, examples and evidence tools exist, the commands below are the
required future command surface, not evidence that the feature has passed. Never point
them at production coordinator, replay, authority or recovery roots.

## 1. Preconditions and safety

- Use the Rust toolchain pinned by `kernel/rust-toolchain.toml` and the committed
  `kernel/Cargo.lock`.
- Use new dedicated local test directories on a provisioner-approved filesystem; do
  not use NFS/SMB, cloud-synchronised folders, removable media or production roots.
- Use only reviewed public synthetic keys, messages and authentication-evidence
  sentinels. Never copy a private key, bearer token, real WebAuthn assertion or user
  message into fixtures or logs.
- Keep the PLAN-006 HLXA authority root separate from the coordinator V2, PLAN-003
  replay and PLAN-005 inbox roots.
- Run destructive migration, corruption, crash, restore and removal cases only against
  disposable roots or detached repository copies created by their harnesses.
- Hosted CI provides synthetic portability and diagnostic timing only. It does not
  establish physical power-loss, physical-M4, production ingress or Tier-1 evidence.

From the repository root, inspect the pinned environment:

```sh
cd kernel
rustc --version --verbose
cargo --version --verbose
cargo metadata --locked --no-deps --format-version 1
```

After implementation, metadata must list exactly these new packages in addition to the
frozen baseline packages:

```text
helix-task-authority-contracts
helix-task-authority
helix-task-authority-sqlite
helix-task-authority-projections
```

No existing PLAN-001/002/004/005 or protected legacy package may gain a reverse
dependency on PLAN-006.

## 2. Frozen prerequisite baseline

Run the existing packages before PLAN-006-specific tests:

```sh
cargo test --locked -p helix-contracts
cargo test --locked -p helix-plan-eligibility
cargo test --locked -p helix-replay-sqlite
cargo test --locked -p helix-plan-preparation
cargo test --locked -p helix-coordinator-sqlite
cargo test --locked -p helix-dispatch-contracts
cargo test --locked -p helix-plan-dispatch
cargo test --locked -p helix-dispatch-inbox-sqlite
```

Expected:

- PLAN-001 canonical plan bytes and IDs are unchanged;
- PLAN-002 keeps its existing evaluation and marker semantics;
- PLAN-003 keeps a separate replay namespace;
- PLAN-004 keeps its ordered guards and commit protocol;
- PLAN-005 keeps its one-shot no-delivery dispatch protocol and closed dependency gate;
- no legacy package becomes an authority provider.

## 3. Fast quality gate

```sh
cargo fmt \
  --package helix-task-authority-contracts \
  --package helix-task-authority \
  --package helix-task-authority-sqlite \
  --package helix-task-authority-projections \
  -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Then compile the non-default evidence surfaces explicitly:

```sh
cargo check --locked -p helix-task-authority-sqlite \
  --features test-fault-injection --all-targets
cargo clippy --locked -p helix-task-authority-sqlite \
  --features test-fault-injection --all-targets -- -D warnings
cargo check --locked -p helix-task-authority-sqlite \
  --features controlled-benchmark --all-targets
```

Expected: `#![forbid(unsafe_code)]`, no formatting or lint drift, no default-build
fault hook, no network/async runtime, and no dependency from an existing plan crate
toward PLAN-006. Formatting is deliberately limited to the four PLAN-006 packages;
the 27 user-owned Rust files under `helixos-kernel`, `helixos-mcp-shim` and
`helixos-provision` are excluded from every format, edit and staging operation.

## 4. Signed contract gate

```sh
cargo test --locked -p helix-task-authority-contracts --test human_request_grant_contract
cargo test --locked -p helix-task-authority-contracts --test task_lease_contract
cargo test --locked -p helix-task-authority-contracts --test approval_decision_contract
cargo test --locked -p helix-task-authority-contracts --test property
cargo test --locked -p helix-task-authority-contracts --test portability
cargo test --locked -p helix-task-authority-contracts --test redaction
```

Expected `PLAN006-CONTRACT` evidence:

- exact RFC 8785 protected and outer bytes, SHA-256 digests and Ed25519 results;
- distinct schemas, signer purposes and signature domains for all three contracts;
- duplicate, unknown, unsupported, noncanonical and tampered inputs deny;
- every protected authority leaf mutation invalidates the original signature;
- public errors and debug output reveal no seeded message, assertion, identifier,
  digest, path, key or provider sentinel;
- the unchanged corpus produces byte-identical summaries on all target OSes.

## 5. Request, lease and terminal-decision gates

```sh
cargo test --locked -p helix-task-authority --test request
cargo test --locked -p helix-task-authority --test delegation
cargo test --locked -p helix-task-authority --test decision
cargo test --locked -p helix-task-authority --test revocation
cargo test --locked -p helix-task-authority-sqlite --test contract
cargo test --locked -p helix-task-authority-sqlite --test contention
```

Run the controlled release workloads separately:

```sh
cargo test --locked --release -p helix-task-authority-sqlite \
  --test contention -- --ignored --nocapture
cargo test --locked --release -p helix-task-authority \
  --test delegation_property -- --ignored --nocapture
```

Expected:

- `PLAN006-REQUEST`: 10,000 sequential exact retries, 100 rounds x 64 threads and
  20 rounds x eight processes retain one root chain and identical retry bytes;
- `PLAN006-LEASE`: 100,000 generated cases admit exact limits and reject every
  widening, union, overflow, underflow and aggregate sibling oversubscription;
- `PLAN006-DECISION`: approve/deny races retain one immutable terminal result and
  every plan, operation, nonce, grant, lease, risk, evidence, session or deadline
  mutation denies;
- expiry, reboot or any source/ancestor/decision revocation removes current authority
  without rewriting retained signed bytes.

## 6. Exact projection and ordered-guard gate

```sh
cargo test --locked -p helix-task-authority --test projection
cargo test --locked -p helix-task-authority-projections --test plan002
cargo test --locked -p helix-task-authority-projections --test plan004
cargo test --locked -p helix-task-authority-projections --test plan005
cargo test --locked -p helix-task-authority-projections --test guard_order
cargo test --locked -p helix-task-authority-projections --test portability
cargo test --locked -p helix-task-authority-projections --test redaction
```

Expected `PLAN006-PROJECTION` evidence:

- PLAN-002 receives the exact TaskLease digest/generation, HumanRequestGrant source
  digest, plan-bound lease projection digest and ApprovalDecision digest/generation;
- ancestor-vector, plan-bound-lease and revocation-vector JCS/digests match their six
  frozen golden files, and mutation of every closed preimage leaf or array order denies;
- PLAN-004 uses `PreparationAuthoritySourceV1` without changing `prepare_plan_v1`;
- PLAN-005 uses `DispatchAuthorityProviderV1` and `DispatchGuardProviderV1` without
  changing `dispatch_prepared_once_v1` or the dispatch crate dependency set;
- acquisition is exactly Recovery, Clock, Supervisor, Signer, Workload, Lease,
  Authorization, Policy, Catalogue, Capabilities, followed by the existing coordinator
  writer, with reverse release;
- Lease opens one HLXA `BEGIN IMMEDIATE`; Authorization validates inside that same
  snapshot; the guard remains held through the existing downstream commit call, and
  no Clock/Signer/Workload/Policy/Catalogue provider is called or acquired under HLXA;
- every single digest, generation, ancestor, revocation, status, identity or deadline
  mutation denies with zero corresponding downstream mutation.

Legacy-specific cases must prove that raw rows, booleans, approval enums, protected
legacy runtime objects, synthetic positive views and historical unsigned state cannot
construct `CurrentAuthorityProjectionV1`. Existing public PLAN-002 fixture constructors
remain test scaffolding only.

## 7. Deadline and TOCTOU gate

```sh
cargo test --locked -p helix-task-authority-sqlite --test contention -- --nocapture
cargo test --locked -p helix-task-authority-projections --test plan004 -- --nocapture
cargo test --locked -p helix-task-authority-projections --test plan005 -- --nocapture
cargo test --locked -p helix-task-authority-projections \
  --test guard_order -- --nocapture
```

Expected:

- equality with any exclusive UTC expiry or monotonic deadline denies;
- clock rollback, monotonic rollback, reboot, generation/boot/instance mismatch,
  overflow and unavailable time fail closed;
- a revocation or generation writer that wins before HLXA acquisition causes final
  denial;
- a downstream commit permit that wins while the unified guard is held is ordered
  before the later authority mutation;
- blocking writer acquisition respects the original absolute deadline, releases prior
  guards in reverse order and leaves no detached late mutation;
- no test claims that the authority and coordinator databases share one transaction.

## 8. HLXA bootstrap and migration gate

PLAN-006 uses a separate authority root:

```text
application_id = 1212962881 (0x484c5841, "HLXA")
user_version   = 1
```

Validate fresh bootstrap and restart classification:

```sh
cargo test --locked -p helix-task-authority-sqlite --test bootstrap_migration \
  -- --nocapture
cargo test --locked --release -p helix-task-authority-sqlite \
  --features test-fault-injection \
  --test bootstrap_migration -- --ignored --nocapture
```

Expected `PLAN006-RESTORE` migration evidence:

- ordinary open accepts only an already-published exact HLXA v1 root and never repairs
  or migrates it;
- explicit paused bootstrap verifies the exact PLAN-005 coordinator-V2 baseline and a
  fresh backup before staging a new empty authority root;
- the migration receipt binds source summary, schema digest and one bootstrap identity;
- restart resumes that identity or recognizes the exact published result once;
- wrong application ID, newer/unknown version, downgrade, partial/corrupt schema and
  reused or conflicting bootstrap identity fail closed;
- no legacy or synthetic lease, approval, row or boolean is inserted as signed
  authority.

## 9. Durability, crash and exact-readback gate

```sh
cargo test --locked -p helix-task-authority-sqlite --test process_crash \
  --features test-fault-injection -- --nocapture
cargo test --locked -p helix-task-authority-sqlite --test corruption -- --nocapture
cargo test --locked -p helix-task-authority-sqlite --test retention -- --nocapture
```

The release process-kill matrix is deliberately ignored by default:

```sh
cargo test --locked --release -p helix-task-authority-sqlite \
  --features test-fault-injection \
  --test process_crash -- --ignored --nocapture
```

Expected `PLAN006-DURABILITY` evidence:

- every declared transition reopens as healthy absence, one complete exact graph or
  explicit ambiguity;
- exact retries return retained bytes; no uncertain operation is blindly re-signed or
  reissued;
- only an explicit uncertain commit receives one fresh non-mutating exact readback;
- signed wires, claims, allocations, counters, generations, key history, revocations,
  events and tombstones remain coherent;
- default builds contain no environment-selected or process-kill fault hook.

Process-kill evidence is labelled as such. It is not physical power-loss evidence.

## 10. Backup and clean-root restore gate

```sh
cargo test --locked -p helix-task-authority-sqlite --test backup_restore \
  -- --nocapture
cargo test --locked -p helix-task-authority-sqlite --test backup_restore \
  --features test-fault-injection -- --nocapture
cargo test --locked -p helix-task-authority-sqlite --test redaction -- --nocapture
```

Expected:

- backup is checkpoint-bound, runs under PAUSE/fixed custody, and publishes its
  top-level manifest last;
- the manifest verifies under the distinct `backup-provisioner-signing` purpose
  and `HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0` domain only through an externally
  provisioned trust resolver; embedded keys must byte-match it, cannot self-authenticate
  their containing package and cannot create task authority;
- every authority and required prior-store member has exact identity, length, digest,
  generation and provenance binding;
- public verification-key history, counters, allocations, revocations and tombstones
  are present; private keys and forbidden raw material are absent;
- corrupt, missing, extra, substituted, stale or provenance-mismatched packages deny;
- restore targets approved empty destinations, rotates root/boot/instance/fencing/
  restore epochs, publishes `RESTORE_PENDING` and remains PAUSED;
- historical signatures verify but zero restored nonterminal lease or approval becomes
  current, and no reissue, replay release, redelivery or host effect occurs;
- the package proves a quiescent coherent cut, not cross-store transaction atomicity or
  full-machine recovery.

## 11. Portable corpus

Materialize the unchanged common corpus and machine-readable summary:

```sh
cargo run --locked -p helix-task-authority-sqlite \
  --features test-fault-injection \
  --example durable_task_authority_corpus -- \
  --output ../artifacts/plan006-corpus-summary.json
```

The same command and fixture bytes run on macOS arm64, Linux x64 and Windows x64.
`PLAN006-PORTABILITY` requires byte-identical common outcomes. OS-specific filesystem
identity or process harness evidence is reported separately and may not alter common
contract semantics.

## 12. Performance and overload gate

Run controlled release benchmarks only on a declared local evidence profile:

```sh
cargo run --locked --release -p helix-task-authority-sqlite \
  --features controlled-benchmark \
  --example durable_task_authority_benchmark -- \
  --output ../artifacts/plan006-benchmark.json
cargo test --locked --release -p helix-task-authority-sqlite \
  --test queue_control -- --ignored --nocapture
```

Expected `PLAN006-PERFORMANCE` evidence:

- after 500 warmups and 10,000 raw measured samples, three-contract verification plus
  projection is p95 <= 2 ms;
- durable root issue, delegation and terminal decision each have independent raw sample
  series with p95 <= 25 ms and p99 <= 100 ms;
- 100 trials x 10,000 duplicate requests bound or refuse new work within 50 ms;
- current revocation and status lookup remain p99 <= 100 ms during the flood;
- hardware, OS/architecture, Rust/SQLite identity, filesystem, durability profile,
  schema/source/lock digests, corpus, concurrency, raw order and percentile method are
  recorded.

Hosted workflow timings are diagnostic and cannot satisfy the physical reference gate.

## 13. Supply-chain and exact-removal gate

If continuing from `kernel/`, return to the repository root after all implementation
commits are present:

```sh
cd ..
python3 tools/plan006_supply_chain.py build \
  --repository . \
  --source-commit "$(git rev-parse HEAD)" \
  --output /tmp/plan006-supply
python3 tools/plan006_supply_chain.py verify \
  --repository . \
  --output /tmp/plan006-supply \
  --require-exact
python3 tools/plan006_removal_drill.py \
  --repository . \
  --baseline c324f528dc76007a599005e5cc054dcbe1370b1a \
  --source-commit "$(git rev-parse HEAD)" \
  --output /tmp/plan006-removal.json
python3 tools/tests/test_plan006_evidence.py
```

`PLAN006-SUPPLY` must bind one exact commit, toolchain, dependency inventory, licenses,
advisories, workflow descriptor, fixture/schema digests and provenance. The removal
drill runs in a detached clean copy, removes all PLAN-006 executable surfaces, restores
baseline-modified files, and requires the indexed tree and package set to equal:

```text
baseline commit: c324f528dc76007a599005e5cc054dcbe1370b1a
baseline tree:   c70a3f2157498dd880822f97ef74d3d4757347d7
```

It then runs the locked/offline PLAN-001 through PLAN-005 and protected legacy package
tests. Source removal is not secure erasure or production decommissioning.

## 14. Final release checks and nonclaims

From the repository root:

```sh
python3 tools/update_roadmap.py
python3 tools/update_roadmap.py --check
git diff --check
```

The release catalogue may register only `REQUEST-001`, `SEC-002` and `SEC-003` for
PLAN-006, and all remain `pending-evidence` until their exact immutable gates pass.

Passing this quickstart does not claim production request ingress, WebAuthn/passkeys,
production key custody, host effects, adapter delivery, effect verification, physical
power-loss durability, secure erasure, distributed commit, cross-store atomic live
backup, full-machine restore, hosted physical-M4 evidence, R2 activation or Tier-1
readiness.
