# PLAN-004 Local Validation

**Captured**: 2026-07-12

**Clean benchmark source commit**: `f7b021db52503aaedcc59b9c9c8d95d357555352`

**Evidence class**: retained local validation from an exact clean source commit; not immutable release evidence

This record contains no native test paths, user identifiers, plan payloads, key
material, provider bindings, device identifiers or volume identifiers. The physical
benchmark started from a detached clean worktree at the exact commit above and created
new dedicated local roots. Its JSON files are retained in this repository with local
SHA-256 digests, but no immutable CI preservation URL, artifact attestation or release
catalog claim exists yet.

## Environment and reviewed inputs

| Item | Captured value |
|---|---|
| Hardware | Mac mini, Apple M4, model `Mac16,10`, 10-core CPU, 16 GB RAM, internal SSD |
| OS | macOS `26.5.2`, build `25F84`, `arm64` |
| Rust | `1.96.1 (31fca3adb 2026-06-26)`, host `aarch64-apple-darwin`, LLVM `22.1.2` |
| Cargo | `1.96.1 (356927216 2026-06-26)` |
| Filesystem assurance label | `validated-local-APFS-internal-SSD-lock-create-sync-primitives` |
| At-rest observation | `FileVault-on-internal-APFS-observed-local` |
| `kernel/Cargo.lock` SHA-256 | `ede1e9ac8e936efc4c65cf99a2fc79ca037934b5aabeac783b1ba265b1c6687f` |
| Locked no-dependency metadata SHA-256 | `38327f54af1883a6a07392084138074619e4dd09fc115364376afb1c743948e2` |
| Reviewed dependency-tree artifact SHA-256 | `36e7c81a8bc3296be2e510c2c4c7db49a719ebcd3c559f1ea4c0d4412aca4f76` |

FileVault being enabled was observed locally; it is not an approved at-rest profile,
a cryptographic qualification or an authorization claim. The benchmark deliberately
records only bounded, non-identifying environment labels.

## Quickstart sections 1–15

Every command and interpretation gate in sections 1–14 was rerun from the clean
detached source commit `f7b021db52503aaedcc59b9c9c8d95d357555352`. The exact
benchmark example passed 7/7, workspace and fault-feature quality gates passed, and the
worktree remained clean after validation. Section 15 then ran alone from the same exact
clean commit with fresh create-new roots and artifacts. An earlier clean attempt at
`32c6e27d3377df96357452ff5631262d15860888` exposed the bounded benchmark defect
described below and produced no artifact.

| Quickstart section | Exact retained local result |
|---|---|
| §1 Preconditions | Rust and Cargo `1.96.1`; locked metadata resolved both PLAN-004 packages without changing `Cargo.lock`. |
| §2 Frozen prerequisite baseline | `helix-contracts`: 56 passed, 1 ignored; `helix-plan-eligibility`: 55 passed, 2 ignored; `helix-replay-sqlite`: 103 passed, 9 ignored. |
| §3 Fast quality gate | Exact package formatting passed. Workspace check, strict Clippy and tests passed; Cargo targets reported 830 passed and 18 intentionally ignored, or 832 passed when the two worker sub-harness tests are included. Fault-feature check and strict Clippy passed. |
| §4 Contract and type boundary | Preparation claims 5/5, portable preparation contract 10/10, coordinator contract 22/22. |
| §5 Fresh comparison and replay verification | Freshness 22/22; replay preparation verification 6/6. |
| §6 Budget exactness and reconciliation | Budget 4/4; property suite 2/2, including 100,000 deterministic vectors; cancellation 13/13. |
| §7 Recovery provider protocol | Portable recovery 17/17; coordinator recovery integration 62 passed, 0 failed, 1 private/release child ignored. |
| §8 Thread and process contention | Normal suite 18 passed, 4 release tests ignored; explicit release suite 4/4 in 189.31 s. |
| §9 Deadline, revocation and no detached work | Deadline 18 passed, 1 release gate ignored; revocation 19/19; explicit held-writer release gate 1/1 in 346.14 s. |
| §10 Deterministic crash and ambiguity matrix | Exact release driver 5/5 in 16.71 s, 77 non-selected tests filtered; 123 unique real fault boundaries and 167 expanded controlled cases. |
| §11 Schema, corruption and no-pruning checks | Schema corruption 53/53; retention 27/27. |
| §12 Quiescent backup and clean restore | Backup/restore 22/22. |
| §13 Versioned conformance and portability | Plan conformance 4/4; coordinator conformance 4/4; fault-feature conformance 25/25. Corpus runner: 335 cases — 3 prepared, 299 denied, 21 failed and 12 ambiguous — with 123 fault boundaries. |
| §14 Redaction, dependency and removal proof | Plan redaction 4/4; coordinator redaction 4/4; restore maintenance API 3/3; portability 8/8; both locked dependency-tree commands exited 0. |
| §15 Physical M4 release benchmark | Clean `f7b021d...` source; 500 warmups, 10,000 measured samples, 10,500 committed operations; p95 and p99 limits passed; separate 16 MiB recovery transfer verified. |

Across sections 8–14, all 19 commands exited 0 and the test suites contributed 219
passes with zero failures. The five ordinary ignored release gates were each executed
by their explicit release command.

The frozen corpus and schema identities retained by the benchmark are:

| Artifact | SHA-256 or count |
|---|---|
| Cases | `086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d` |
| Expected outcomes | `87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b` |
| Canonical corpus summary | `e0dac29c01276a7f6168a83bff51accefc86a129f1046065ebea5f136bbddd87` |
| Coordinator schema | `e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e` |
| Backup manifest schema | `163cfd72f54983f993b2d5f6ad3fcd00df84a1b8cbc7eb971fcc8c1d0019199e` |
| Provenance attestation schema | `6b752fc1a8f0c92fd69a03ce418d07087e615eaf55f3b2e1959668e15237728f` |
| Recovery root schema | `0fb080c12df1b1e99ef7d0a19ca53ded97d8d170e0c2825e93fd3d57c53bf25f` |
| Recovery snapshot schema | `371e94fbf5c52d462e8363c9b3237a57288c4b0ae1c766e12c2c904d5f6cf646` |

## First physical run: retained dead end

The first clean attempt at `32c6e27...` stopped after 239 committed operations with
`CONTROLLED_BENCHMARK_PREPARATION_REFUSED`. No evidence artifact was created. The last
successful operation had consumed 199,728 ms of a 200,000 ms local capability age,
leaving only 272 ms before the next operation. The coordinator database remained
healthy (`quick_check` passed, foreign keys were clean), so the stop was a fail-closed
benchmark refusal rather than corruption.

The cause was twofold:

- the signed benchmark capability used a 200 s maximum age even though merely
  pre-provisioning 10,500 scopes at 25 ms each can exceed 262.5 s; and
- the normal preparation path performed four historical `verify_full` global scans
  per operation. Those signature, canonicalization, digest, history and aggregate
  scans made the workload quadratic even though the production contract requires a
  bounded active-operation proof on the hot path.

The correction binds capability age to the signed plan expiry and adds a persistent
query-only observer using SQLite `PRAGMA data_version`. If another connection commits,
the next preparation performs the full historical verification before proceeding.
Without an external commit, the hot path verifies the embedded schema identity,
application/user identity, schema cookie, bound root identity/lifecycle, generation
vector and the exact eight-member staged preparation postcondition. Full verification
remains mandatory on open/reopen, external change, uncertain readback and
maintenance/backup/restore paths. A regression test mutates an older comparison row
from a second connection and proves that the next preparation fails closed after the
observer forces full verification.

## Successful clean physical-M4 run

The corrected benchmark ran alone from a clean detached worktree at
`f7b021db52503aaedcc59b9c9c8d95d357555352`, with new coordinator and recovery roots.
It exercised `prepare_plan_v1` through the production coordinator commit and returned
outcome boundary at concurrency 1. Eligibility and budget-scope provisioning occurred
outside measured samples, and the recovery transfer remained outside coordinator
percentiles.

| Measurement | Result |
|---|---:|
| Warmup operations | 500 |
| Measured sorted samples | 10,000 |
| Total committed operations | 10,500 |
| p50 | 11,218,708 ns |
| p95 | 24,096,375 ns |
| p99 | 25,443,666 ns |
| maximum | 26,528,459 ns |
| p95 limit | 25,000,000 ns — pass |
| p99 limit | 100,000,000 ns — pass |
| Final store / operation / budget / event generations | 21,000 / 10,500 / 21,000 / 10,500 |
| Close/reopen, `quick_check`, foreign keys | pass / pass / pass |

Retained artifacts:

| Artifact | SHA-256 | Notes |
|---|---|---|
| `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.json` | `ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12` | 10,000 raw sorted coordinator samples; exact clean commit recorded |
| `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.recovery-transfer.json` | `da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e` | separate 16 MiB transfer; 66,358,167 ns total; excluded from coordinator percentiles |

The recovery transfer wrote, synchronized, closed, reopened and rehashed 16,777,216
bytes. Its source and reopened material digest both equal
`55c7e25571a69216de25162f191bb2847201a09ee7efe46b5bada034acc695d5`.
This public synthetic transfer is not production compensability evidence.

## Local process-kill result and remaining gates

The T074 explicit-session release driver passed locally: five ignored harness tests
executed the exhaustive parent, covering 123 real fault boundaries and 167 controlled
cases. This is a local synthetic process-kill result. It is not power-loss evidence and
still lacks an immutable CI artifact, preservation URL and attestation.

The following remain pending and prevent a release or Tier 1 claim:

- unchanged immutable Linux x64, macOS arm64 and Windows x64 CI artifacts;
- SBOM and license archive for the exact lockfile and bundled SQLite source;
- RustSec scan with scanner/database identity and complete retained output;
- artifact and build-provenance attestations, immutable preservation URLs and
  uploaded-artifact digest bindings for the physical benchmark and process-kill matrix;
- approved at-rest qualification; local FileVault was only observed;
- production recovery-provider qualification, power-loss/sector-loss and
  directory-`fsync`/secure-erasure evidence; and
- full-machine restore, activation/dispatch authority and Tier 1 approval.

## Interpretation

The clean physical-M4 benchmark satisfies the local synthetic p95/p99 performance
thresholds for the exact source commit and the local suites support the named
PLAN-004 contracts. These files do not make the artifacts immutable, approve the
observed FileVault configuration, establish production compensability or durability
under power loss, or grant preparation, dispatch, recovery, activation or Tier 1
authority. The catalog must therefore remain `pending-evidence` until the external and
immutable gates above are completed.
