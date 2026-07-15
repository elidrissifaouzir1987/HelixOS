# PLAN-005 physical Mac mini M4 performance remediation

- **Recorded**: 2026-07-14
- **Final run window**: 2026-07-14T17:55:02Z through 2026-07-14T18:28:54Z
- **Final wrapper wall time**: 2,031.76 seconds
- **Branch**: `codex/plan-005-durable-dispatch`
- **Baseline HEAD**: `6f8dfdd5194792e8592cd10ebaaf8828833effbe`
- **Source state**: local PLAN-005 working tree, not an exact committed or immutable checkout
- **Evidence class**: controlled physical Mac mini M4 local working-tree evidence
- **SC-005 physical percentile result**: pass
- **PERF-002 physical threshold status**:
  `passing-controlled-physical-local-working-tree-not-immutable`

T095 retained the original failed T091 evidence byte-for-byte, added deterministic phase
characterization, applied four reviewed production-remediation waves, and retained every exact
physical rerun. The first three remediation artifacts still miss p95 and were not replaced or
discarded. The fourth create-only run satisfies both SC-005 limits with 10,000 measured samples:
p95 is 49.416541 ms and p99 is 51.917875 ms.

This result closes the local physical percentile gate only. It is not immutable exact-commit,
power-loss, `F_FULLFSYNC`, approved encrypted-at-rest, production supervisor/provider, physical
isolation, full-machine activation or Tier 1 evidence. Aggregate PLAN-005 `claim_status` therefore
remains `pending-evidence`.

## Frozen physical profile and protocol

| Property | Observed value |
|---|---|
| Hardware | Mac mini `Mac16,10`; Apple M4; 10 available logical CPUs |
| Memory | 17,179,869,184 bytes (16 GiB) |
| OS | macOS 26.5.2, build `25F84` |
| Architecture | `arm64`; Rust host `aarch64-apple-darwin` |
| Benchmark-store volume | APFS; internal solid-state device; SMART verified |
| At-rest observation | FileVault `Yes`; observation only, approval still pending |
| Rust | rustc 1.96.1 (`31fca3adb`, LLVM 22.1.2) |
| SQLite | 3.53.2, source ID `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24` |
| Build | Cargo `release`; exact feature `controlled-benchmark` |
| Sleep prevention | `/usr/bin/caffeinate -dimsu` |
| Concurrent Cargo or benchmark work | none |

Every repetition used a fresh coordinator root and a distinct fresh adapter root. The coordinator
used application ID `1212962883`, schema version 2; the adapter used application ID `1212962889`,
schema version 1. Both stores reported `journal_mode=wal`, `synchronous=2` (`FULL`),
`wal_autocheckpoint=0`, `foreign_keys=1`, `trusted_schema=0`, `cell_size_check=1`,
`recursive_triggers=1` and a 30,000 ms busy-wait bound.

The measured interval begins at the first instruction of fixed-order final-guard acquisition. It
includes the production coordinator dispatch commit, durable possible-handoff evidence,
independent adapter receive and consume, signed receipt production, and coordinator receipt
commit. It ends immediately after external validation that the receipt commit returned
`Committed` with effective state `EXECUTING`. Authentic preparation, fresh-root provisioning and
per-cycle wiring remain outside the interval. `EXECUTING` is consumed no-effect authority, not a
host effect or execution-success claim.

| Workload property | Exact value |
|---|---:|
| Warmups | 500 |
| Measured operations / raw samples | 10,000 / 10,000 |
| Total unique operations | 10,500 |
| Committed `EXECUTING` receipts | 10,500 |
| Workload concurrency | 1 |
| Coordinator ordinary / control capacity | 1,024 / 32 |
| Adapter ordinary capacity | 1,024 |
| Queue depth at each new dispatch | 0 |
| Retained preparations / grants per fresh root | 1 / 1 |
| Grant lifetime | 5,000 ms |
| Nominal WAL/FULL commits per operation | 5 |

The final command was:

```shell
cd kernel
/usr/bin/time -p caffeinate -dimsu cargo run --locked --release \
  -p helix-coordinator-sqlite \
  --example durable_dispatch_benchmark \
  --features controlled-benchmark -- \
  --warmups 500 \
  --samples 10000 \
  --output ../specs/005-durable-dispatch/evidence/m4-remediation-4-raw.json
```

## Remediation design

The benchmark schema was advanced to `helixos.durable-dispatch-benchmark/3`. Five timestamps on
one `std::time::Instant` timeline partition every measured sample exactly into:

1. final-guard entry to coordinator dispatch commit;
2. dispatch commit to acknowledged adapter handoff;
3. handoff acknowledgement to adapter consumption;
4. adapter consumption to coordinator receipt commit.

The production changes applied across the four remediation waves were:

- bind an acknowledged delivery attempt directly in the receipt transaction instead of running
  possible-handoff readback after a transport acknowledgement;
- consolidate connection PRAGMA setup/verification, replace uniqueness-backed `COUNT(*)=1`
  probes with existence checks where cardinality is already frozen, and retain the same strict
  anti-shadow and schema checks;
- avoid a redundant current-grant duplicate preflight while preserving the historical exact-only
  path, and expose only the opaque retained grant correlation ID needed by the handoff caller;
- remove a benchmark-only timed SQLite grant-ID reread; the production handoff still reloads and
  verifies the exact retained grant, outbox and root custody;
- keep one independent read-only epoch-observer connection open outside the interval while each
  observation executes a fresh autocommit query and therefore refreshes its WAL snapshot;
- verify a current adapter grant cryptographically once, using the evidence decoder only after the
  current decoder explicitly returns `HistoricalKeyNotAuthority`;
- remove four connection-profile PRAGMA reads already proved by the complete V2 verifier on the
  same private `BEGIN IMMEDIATE` connection;
- reuse the receipt context and reconciliation high-water already loaded in the same writer
  snapshot instead of repeating a nine-table join and metadata query.

These are production-path changes, not benchmark-only bypasses. Fixed guard order, exact signed
bytes, current-versus-historical authority, independent clock/epoch observations, root/file
custody, WAL/FULL, `BEGIN IMMEDIATE`, CAS predicates, generation high-water checks, post-stage
foreign-key and complete V2 graph verification, and uncertain-commit custody remain enforced.
Independent reviews returned GO for the retained-grant correlation API, persistent observer
lifecycle and fourth remediation wave.

## Complete physical result history

Percentiles below were independently recomputed using the exact nearest-rank rule. All failed
artifacts remain evidence; no partial or selective rerun replaced them.

| Run | p50 | p95 | p99 | Maximum | p95 result | p99 result |
|---|---:|---:|---:|---:|---|---|
| Original T091 | 58.029834 ms | 66.797000 ms | 83.636542 ms | 289.463209 ms | miss by 16.797000 ms | pass |
| Remediation 1 | 46.675542 ms | 51.087750 ms | 54.176583 ms | 91.236667 ms | miss by 1.087750 ms | pass |
| Remediation 2 | 46.978208 ms | 50.993542 ms | 55.019375 ms | 87.097416 ms | miss by 0.993542 ms | pass |
| Remediation 3 | 44.310000 ms | 50.030833 ms | 52.182792 ms | 80.315959 ms | miss by 0.030833 ms | pass |
| **Remediation 4** | **45.431542 ms** | **49.416541 ms** | **51.917875 ms** | **76.199000 ms** | **pass by 0.583459 ms** | **pass by 48.082125 ms** |

The final p95 is 17.380459 ms below the original physical result. The higher final p50 than
remediation 3 is retained rather than hidden; SC-005 gates p95 and p99, both of which improved and
pass in the final complete run.

### Exact p95 phase characterization

| Run | Dispatch commit | Handoff ACK | Adapter consume | Receipt commit |
|---|---:|---:|---:|---:|
| Remediation 1 | 18.581500 ms | 17.023250 ms | 1.176459 ms | 14.383416 ms |
| Remediation 2 | 18.535667 ms | 16.982666 ms | 1.185250 ms | 14.415417 ms |
| Remediation 3 | 18.615000 ms | 16.113667 ms | 0.832875 ms | 14.510875 ms |
| Remediation 4 | 18.540667 ms | 15.851000 ms | 0.837000 ms | 14.269125 ms |

Each individual sample, rather than the percentile row, is the exact sum of its four phase
durations. Phase percentiles are independently ranked and are not expected to sum to the total
percentile.

## Create-only artifacts and bindings

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `m4-raw.json` | 165,212 | `fcf86188a41c49a4ef2def0116e614cde8125e5164be95f2a5916bfc94738983` |
| `m4-remediation-raw.json` | 2,985,161 | `b67941730e07abbe76629e3510c3ff203e418e2a7e5e92d405c276e635b54870` |
| `m4-remediation-2-raw.json` | 2,985,674 | `0382871d78260bd321d0a6f7d707a2da556e9addeef80af0abd33b10676c7454` |
| `m4-remediation-3-raw.json` | 2,976,408 | `07daefe5621f8843690108f51188151a04052c5a53e168192b76399eba742104` |
| `m4-remediation-4-raw.json` | 2,976,416 | `c37c2d3dde82bcb7da86b0400e4abccf64a0358a4a056f0aad8a8e9396af343f` |

The final raw artifact binds:

| Input | SHA-256 |
|---|---|
| Release executable | `dab3ddda879e6a1ed441521a807c888d7256dd9eec6265eac1006b510a077113` |
| Benchmark source | `c00e7bfd04701aef41579cfe6b2b5974432e10cfdb0e78ad2e8499836fcabaf0` |
| `kernel/Cargo.lock` | `17b1355d76b855d5923b8223e58939dad1b6d76368d9aa1ae59046e8094b5c60` |
| Coordinator base schema V1 | `e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e` |
| Coordinator dispatch schema V2 | `ee05a9e4db7934ae6ba2be9536595c0b100fec7bc3d8991d884674aa1ceb2440` |
| Adapter inbox schema V1 | `f6d4917175038ff726ec6d27a1c59de7210f58a1079cf428586130862c050724` |
| 10,500 canonical benchmark plans | `cb3ad4bebabdef1afc6c47be918f78c23f4477e1a950e2834561cfc38d0bbeb6` |
| Contract cases | `70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a` |
| Expected outcomes | `8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4` |
| Fault boundaries | `041c2eca7dfdc5b3c3a0a7b5a3d1399c26133f9fe63e8a26e23c9bc9bab7ef3b` |

## Post-remediation diagnostic integrity

The fail-closed removal policy was refreshed only for the newly modified coordinator corruption
test. The protected manifest now contains 22 explicit baseline paths and has SHA-256
`c45caacf0184c9e0150122b89887037b01b92d9bf3163d583399d9b911d13a7a`; no exclusion or prefix
was broadened.

A fresh external diagnostic removal drill completed successfully against the uncommitted working
tree. It protected all 495 baseline leaf blobs, restored the 22 explicit baseline paths, removed
149 added implementation paths, retained 35 audit paths, and left only the eight baseline/legacy
packages after removal. All five offline semantic test commands returned zero. The retained report
has SHA-256 `a141d5ac44f1cc13e881344009087b022e3922045f84d6e6d9cc0bdbede75601`,
and its source-delta binding is
`24e5898e3ec445c59a8e5f753441c389904af3fb563d51931e9eea85d3af3014`. This is explicitly
`diagnostic-uncommitted-working-tree-snapshot`, not immutable removal evidence.

## Validation and interpretation

Before the final physical run, validation passed:

- adapter full suite, including current/historical keys, corruption, contention, restart,
  receipts, redaction and stale-epoch cases;
- coordinator library: 149 passed;
- targeted dispatch, commit, receipt and corruption integrations;
- schema corruption: 86 passed, 0 failed, 2 private process children ignored;
- benchmark example: 6 passed, including exact phase partition and fresh WAL observer snapshot;
- end-to-end exact gate: 56 passed, 0 failed, 3 private children ignored, including 10,000
  sequential duplicates, 100 rounds × 64 threads and 20 rounds × 8 processes;
- fault matrix: 54 passed, 0 failed, 6 release/private cases ignored; and
- workspace Clippy with all targets, all features and warnings denied.

Independent post-run validation found zero errors and proved:

- exactly 10,000 result samples and 10,000 phase samples;
- every total equals its four ordered phase durations;
- exact nearest-rank p50, p95, p99 and maximum, including every phase summary;
- exactly 10,500 unique cycles and 10,500 committed `EXECUTING` receipts;
- exact workload, physical profile, WAL/FULL store profiles, source, executable, Cargo.lock,
  schema and corpus bindings; and
- no private path, username, PAT, access-token marker or private-key header in the artifact.

The raw executable intentionally retains `local-diagnostic`, `diagnostic_only=true`,
`physical_m4_claim=false`, `acceptance_gate_evaluated=false` and
`reference_limits_are_acceptance_verdict=false`. This external wrapper qualifies the observed
host and evaluates SC-005 without pretending that a self-described JSON file or local working
tree is immutable release evidence.

Accordingly, T095 and the controlled physical percentile portion of `PERF-002` pass. Immutable
exact-commit evidence, approved encrypted-at-rest qualification, `F_FULLFSYNC`/power-loss,
production supervisor/IPC/provider, physical isolation, full-machine restore/activation and Tier
1 support remain pending or out of scope exactly as declared in the catalogue.
