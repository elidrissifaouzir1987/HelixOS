# PLAN-004 Local Validation

**Captured**: 2026-07-11
**Base source commit**: `01a9181ef83539c0516139f8285551a9dfabc3b5`
**Evidence class**: local, synthetic, mutable-worktree validation

This record contains no native test paths, user identifiers, plan payloads, key
material or provider bindings. The recovered worktree was intentionally dirty and the
Feature 004 files were not committed, so these results are implementation feedback,
not immutable release evidence or a catalog claim.

## Environment and reviewed inputs

| Item | Captured value |
|---|---|
| Hardware | Apple M4, model `Mac16,10` |
| OS | macOS `26.5.2`, build `25F84`, `arm64` |
| Rust | `1.96.1 (31fca3adb 2026-06-26)`, host `aarch64-apple-darwin`, LLVM `22.1.2` |
| Cargo | `1.96.1 (356927216 2026-06-26)` |
| Free space before final gates | 107 GiB |
| `kernel/Cargo.lock` SHA-256 | `ede1e9ac8e936efc4c65cf99a2fc79ca037934b5aabeac783b1ba265b1c6687f` |
| Locked no-dependency metadata SHA-256 | `38327f54af1883a6a07392084138074619e4dd09fc115364376afb1c743948e2` |
| Reviewed dependency-tree artifact SHA-256 | `36e7c81a8bc3296be2e510c2c4c7db49a719ebcd3c559f1ea4c0d4412aca4f76` |
| Frozen cases SHA-256 | `086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d` |
| Frozen outcomes SHA-256 | `87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b` |
| Coordinator schema SHA-256 | `e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e` |

`cargo metadata --locked --no-deps --format-version 1` listed both Feature 004
packages and resolved without changing the lockfile. The pinned bundled SQLite identity
was `rusqlite 0.40.1`, `libsqlite3-sys 0.38.1`, SQLite `3.53.2`, source ID
`2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.

## Passing local gates

The following commands completed successfully under `--locked`:

| Gate | Exact local result |
|---|---|
| PLAN-001/002/003 prerequisite suites | all ordinary tests passed; the frozen pre-feature totals remain 194 passed, 0 failed, 12 explicitly ignored as recorded in `baseline.md` |
| Contract/type boundaries | preparation claims 5/5, portable contract 10/10, coordinator contract 22/22 |
| Coordinator unit library | 120/120 |
| Freshness and replay verification | freshness 22/22; replay preparation verification 6/6 |
| Budget | 4/4 plus property suite 2/2, including 100,000 deterministic vectors |
| Cancellation | targeted default suite 13/13; all-feature source-expanded suite 24/24 |
| Portable recovery | 17/17 |
| Coordinator recovery integration | 61 passed, 0 failed, 1 private/release child ignored |
| Backup/restore | 22/22 |
| Non-test production conformance | backup 1/1 and restore 1/1 |
| Normal contention | targeted default suite 18 passed, 0 failed, 4 explicitly ignored; all-feature source-expanded suite 45 passed, 0 failed, 6 ignored |
| Release contention | 4/4; 105.77 seconds test time; includes 100 x 64 threads, 20 x 8 processes and shared-allowance coverage |
| Deadline/revocation ordinary coverage | deadline 18 passed plus 1 release gate ignored; revocation 19/19 |
| Release held-writer gate | 1/1; 355.05 seconds test time; 1,000 attempts with the required post-return observation |
| Schema corruption | 53/53 |
| Retention | 27/27 |
| Plan/coordinator redaction | 8/8 combined |
| Plan/coordinator conformance | 8/8 combined |
| Fault-feature conformance execution | 20/20, single-threaded |
| T074 process-kill/fault-injection matrix | 123 unique boundaries / 167 controlled cases passed in the exact release driver on 2026-07-12; 16.18 seconds test time |
| T075/T085 restore public boundary | Option B recorded; internal limit/error 1/1, negative public surface 3/3, redaction 4/4, portability 8/8, targeted all-feature check and strict Clippy passed on 2026-07-12 |
| Portability/removal | coordinator 8/8, replay 9/9, eligibility 6/6 |
| Corpus runner | 335 cases; canonical summary SHA-256 `e0dac29c01276a7f6168a83bff51accefc86a129f1046065ebea5f136bbddd87` |
| Workspace regression | default workspace and final `--all-features` workspace runs completed with zero failures; intentionally ignored release/child workloads remained explicitly labeled |
| Formatting and lint | final workspace formatting, all-target/all-feature check and all-target/all-feature clippy passed with `-D warnings` |

The GitHub workflow YAML parsed locally. Its immutable action tags resolved to the
reviewed commits for checkout v6.0.2, upload-artifact v7.0.1 and attest-build-provenance
v4.1.1. The catalog retained PLAN-001/002/003 as `pending-evidence`, registered exactly
PLAN-001 through PLAN-004 and referenced only existing repository paths.

## Open and failing gates

### T074 exhaustive process-kill matrix — PASS (local synthetic evidence)

Command:

```sh
cargo test --locked --release -p helix-coordinator-sqlite \
  --features test-fault-injection \
  --test process_crash -- --ignored --nocapture
```

The 2026-07-12 rerun passed all five ignored harness tests, including the exhaustive
parent. The frozen inventory remained exact at 123 unique boundaries and 167 expanded
controlled cases. For every case, the caller-owned probe reached the selected real
portable or coordinator action before process termination. Phase-specific reopen checks
accepted only absence, one invariant-valid `PREPARING` operation, one atomic `FAILED`
transition, or explicit quarantine. Registry enumeration and manual checkpoint loops
were not counted as process-kill evidence. This closes T074 as local
process-kill/fault-injection evidence, not as power-loss or immutable release evidence.

### T075/T085 restore public boundary — PASS (Option B)

The accepted 2026-07-12 clarification keeps the sovereign host and activation facade in
a later feature. The default crate surface now exports exactly the non-constructible,
payload-free `VerifiedPreparationRestoreV1` and
`RestoredPreparationMaintenanceEvidenceV1` projections, with private fields and no
public producer. Restore acceptance/validation, old-authority reconciliation,
quarantine, limits/errors/inputs and every PAUSE/fencing/recovery/trust/no-dispatch
authority remain crate-internal. The hidden non-default conformance entrypoints return
only static payload-free test results and are not production maintenance APIs. Internal
limit/error tests passed 1/1, the negative public-surface suite passed 3/3, redaction
passed 4/4, portability/removal passed 8/8, and targeted all-feature check plus strict
Clippy passed. This closes T075 and T085 without claiming a production host or
activation authority.

### T077 benchmark implementation — PASS; immutable physical run pending

The non-default `controlled-benchmark` path passed 6/6 example tests, strict clippy and
a two-operation smoke test. Each smoke operation used a unique signed/authenticated
plan, real eligibility, `prepare_plan_v1`, the production coordinator commit adapter and
a full close/reopen with the retained root identity and historical resolver. L2
irreversible fixtures proved zero recovery-provider calls, so the separate recovery
transfer is not hidden inside the coordinator samples. A release invocation on this
dirty worktree refused before creating either root or either evidence file.

A retained physical-M4 result still requires an exact clean source commit, new
dedicated roots and the two create-new artifacts. The benchmark now also detects an
Apple M4 macOS arm64 host rather than accepting the caller hardware label alone. This
dirty recovered worktree cannot produce an accepted latency artifact.

### Supply chain and external evidence — pending

`cargo-audit` was not installed. This is recorded as **no advisory scan**, not a passing
scan. SBOM, license archive, immutable three-platform CI artifacts, attestations,
production recovery qualification, power-loss/sector-loss evidence, full-machine
restore and activation evidence remain pending exactly as declared in the catalog.

## Interpretation

The green local suites support the named synthetic contracts and show no known
PLAN-001/002/003 regression. Release acceptance is withheld because clean physical-M4
evidence and external supply-chain/durability evidence are incomplete. No result in this
file grants preparation, dispatch, recovery, activation or Tier 1 authority.
