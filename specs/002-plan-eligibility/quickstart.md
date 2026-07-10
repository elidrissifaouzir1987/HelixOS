# Quickstart: Validate Current Plan Eligibility

## What this validation proves

This feature evaluates an already verified `AuthenticPlanEnvelopeV1` against explicit,
trusted current-state evidence and performs the final claim through the
`ReplayClaimantV1` contract. A successful result is an opaque, in-process
`EligiblePlanV1` that is a **point-in-time necessary condition only**.

It is not proof of human approval or WebAuthn verification, durable recovery
preparation, budget reservation, `PREPARING`, an `ExecutionGrant`, adapter inbox
admission, or authority to perform a host effect. No adapter may accept it. Production
replay durability and compare-before-prepare belong to a later durable-coordinator
feature.

## Prerequisites

- Run commands from the repository root.
- Use the exact Rust `1.96.1` toolchain, `rustfmt` and `clippy` components from
  `kernel/rust-toolchain.toml`, plus the committed `kernel/Cargo.lock`.
- Complete the release gates from a clean checkout.
- No native clock, filesystem adapter, credential store, network service, approval UI,
  or production replay database is required for the deterministic feature tests.

## Formatting and strict lint gate

```sh
cargo fmt --manifest-path kernel/Cargo.toml \
  --package helix-contracts --package helix-plan-eligibility -- --check
cargo clippy --locked --manifest-path kernel/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
```

Expected result: formatting is unchanged and Clippy reports no warnings. The strict
workspace lint remains a regression gate even though eligibility itself is a leaf crate.

## Feature-001 contract regression

```sh
cargo test --locked --manifest-path kernel/Cargo.toml \
  -p helix-contracts --all-targets --all-features
```

Expected result: canonical wire decoding, plan identity, signature verification, and the
existing feature-001 fixture corpus remain unchanged. Eligibility must not alter the v1
wire schema, golden envelope, plan ID, or signature behavior.

## Eligibility crate and conformance corpus

```sh
cargo test --locked --manifest-path kernel/Cargo.toml \
  -p helix-plan-eligibility --all-targets --all-features
```

Expected result: the positive case and every single-fault denial in
`contracts/fixtures/plan-eligibility-v1/` produce the declared decision and stable
redacted code. Failed read-only gates must show that the replay claimant was not called.
The eligible case must show exactly one successful claim and no preparation or dispatch
probe.

The committed fixture bytes are the cross-platform corpus. Run the same command without
rewriting, normalizing, regenerating, filtering, or selecting fixtures by operating
system. From a clean checkout, verify that the test did not mutate them:

```sh
git diff --exit-code -- contracts/fixtures/plan-eligibility-v1
git status --short -- contracts/fixtures/plan-eligibility-v1
```

Expected result: the first command succeeds and the second prints nothing. The targeted
crate command is the feature-level portability gate to run unchanged on Linux x86_64,
macOS arm64, and Windows x64.

## Whole-workspace regression

```sh
cargo test --locked --manifest-path kernel/Cargo.toml \
  --workspace --all-targets --all-features
```

Expected result on the current supported development host: feature 001, feature 002,
and the legacy MVP-0 tests all pass.

This workspace command is distinct from the targeted eligibility portability gate. The
legacy workspace currently contains Windows-specific code that may block a complete
workspace macOS build. A green targeted `helix-contracts` plus
`helix-plan-eligibility` run is valid feature evidence, but it must not be presented as a
green legacy workspace or full-system portability result. Conversely, the legacy hazard
must be resolved before an all-green multi-OS workspace or HelixOS Tier 1 claim.

## Deterministic 1,000-round replay contention

```sh
cargo test --locked --release --manifest-path kernel/Cargo.toml \
  -p helix-plan-eligibility --test contention -- \
  --ignored --nocapture --test-threads=1
```

The ignored release test is fixed to at least 1,000 barrier-synchronized rounds. In every
round, concurrent evaluations use one shared deterministic claimant for the same plan and
nonce.

Expected result: exactly one contender obtains `ReplayClaimReceiptV1`; all others receive
the declared replay denial; no round produces zero or multiple winners; and a failed
pre-claim gate consumes no replay state.

This proves the `ReplayClaimantV1` atomicity contract and its deterministic concurrent
test implementation. It is **not** evidence that a production claim survives process
death, reboot, restore, disk failure, or an ambiguous storage outcome. Those properties
remain mandatory work for the durable coordinator.

## Deterministic 100,000-context soak

```sh
cargo test --locked --release --manifest-path kernel/Cargo.toml \
  -p helix-plan-eligibility --test soak -- \
  --ignored --nocapture --test-threads=1
```

Expected result: at least 100,000 generated eligibility contexts complete without panic,
arithmetic overflow, platform-dependent decision drift, or false acceptance. The test
must print the seed/corpus identity, total contexts, eligible/denied counts, elapsed time,
and final status.

## Mac mini M4 reference benchmark

The reference command below is for a real Apple Silicon Mac mini M4. Do not use this
hardware label for Rosetta, a VM, a remote runner, or another machine.

```sh
mkdir -p specs/002-plan-eligibility/evidence
HELIX_BENCH_HARDWARE="Mac mini M4" \
  cargo run --locked --release --manifest-path kernel/Cargo.toml \
  -p helix-plan-eligibility --example eligibility_benchmark -- \
  --evidence specs/002-plan-eligibility/evidence/benchmark-macos-arm64-2026-07-10.json
```

The benchmark must execute at least 10,000 complete evaluations with the deterministic
local claimant and record:

- evidence schema and corpus version/digest;
- exact hardware label, available parallelism, OS/architecture, Rust toolchain and
  release profile;
- declared workload/case, iteration count, claimant concurrency and raw sorted samples;
- p50, p95, p99 and maximum latency;
- winner/denial counts, public fixture case ID and corpus digest; never a runtime plan
  ID or other protected identifier.

The provisional performance gate is p95 at or below 1 ms. Preserve the raw artifact at
the path passed to `--evidence`; do not transcribe only the summary. For a later run, use
a new date-specific filename rather than overwriting immutable release evidence.

On PowerShell, set the same label before running the Cargo command:

```powershell
$env:HELIX_BENCH_HARDWARE = 'Mac mini M4'
```

## Removal-isolation proof

Prove that no existing crate depends on the removable leaf and that the old workspace
continues to pass without selecting it:

```sh
cargo tree --locked --manifest-path kernel/Cargo.toml \
  --workspace --invert helix-plan-eligibility --edges normal
cargo test --locked --manifest-path kernel/Cargo.toml \
  --workspace --exclude helix-plan-eligibility --all-targets --all-features
```

Expected result: the inverse tree contains the eligibility package itself and no
dependent workspace crate; feature-001 golden/signature tests and the legacy MVP-0
tests remain green while the new member is excluded. Together with the source gate that
forbids reverse dependencies, this is the non-destructive removal drill. It does not
delete or rewrite the user's working tree.

## Graphify refresh after verified work

After code, tests, fixtures, and evidence are final:

```sh
graphify update . --force
graphify reflect --if-stale --graph graphify-out/graph.json
```

Persist concise redacted `graphify save-result` records for the key claim-last/
non-authority design decision, the corrected replay-namespace decision, and the final
verified outcome. Add a dead-end record only if one actually occurred. Include relevant
spec/test/evidence paths and mark each outcome `useful`, `dead_end`, or `corrected`. Do
not store fixture payloads, identifiers, nonces, signatures, raw provider errors,
credentials, or private reasoning. Specs, source, fixtures, tests, immutable CI runs,
and evidence artifacts remain authoritative.

## Local evidence versus Tier 1 evidence

A successful local run proves only the recorded checkout, toolchain, hardware and test
inputs:

- A local Windows or Linux run is local correctness evidence only.
- A real Mac mini M4 benchmark is reference-machine performance evidence only.
- The deterministic claimant proves the replay interface and contention behavior, not
  production replay durability.
- Passing `helix-plan-eligibility` does not prove approval, preparation, dispatch,
  adapter execution, recovery, reconciliation, backup/restore, or the whole system.

Feature-level cross-platform evidence requires immutable CI runs for the same commit on
Linux x86_64, macOS arm64, and Windows x64, using the unchanged committed corpus and
publishing the run URLs, exact commit, artifact SHA-256 or attestation, and a preserved
retention location recorded in the conformance catalogue. A URL to an expiring artifact
alone is insufficient. A local result or an emulated architecture must never be
substituted for those runs.

Even after that targeted matrix passes, `EligiblePlanV1` remains only a point-in-time
prerequisite. HelixOS Tier 1 remains blocked until the production durable replay store,
generation compare-before-prepare transaction, approval/WebAuthn verification,
recovery preparation, signed one-shot `ExecutionGrant`, adapter inbox/receipt protocol,
reconciliation, and the remaining constitutional hardware/restore gates have immutable
evidence.
