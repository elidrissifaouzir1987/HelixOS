# PLAN-005 physical Mac mini M4 benchmark evidence

- **Recorded**: 2026-07-14
- **Run window**: 2026-07-14T11:51:21Z through 2026-07-14T12:26:57Z
- **Wrapper wall time**: 2,135.34 seconds
- **Branch**: `codex/plan-005-durable-dispatch`
- **Baseline HEAD**: `6f8dfdd5194792e8592cd10ebaaf8828833effbe`
- **Source state**: local PLAN-005 working tree, not an exact committed or immutable checkout
- **Evidence class**: controlled physical Mac mini M4 local diagnostic with one missed
  performance threshold; not immutable, power-loss, `F_FULLFSYNC`, physical-isolation or
  Tier 1 evidence
- **PERF-002**: `pending-evidence`

T091 ran because the benchmark's actual temporary-store volume and all required
hardware, OS, toolchain and SQLite metadata were available before the timed command. The
run completed all 10,500 unique coordinator-to-adapter cycles and retained all 10,000
post-warmup samples. The p99 threshold passed, but p95 exceeded its limit. The result is
therefore retained without a retry or selection of a more favorable run, and neither
`PERF-002` nor aggregate PLAN-005 status is promoted.

## Qualified physical profile

| Property | Observed value |
|---|---|
| Hardware | Mac mini model `Mac16,10`; Apple M4; 10 physical / 10 logical CPU cores |
| Memory | 17,179,869,184 bytes (16 GiB) |
| OS | macOS 26.5.2, build `25F84` |
| Architecture | `arm64`; Rust host `aarch64-apple-darwin` |
| Benchmark-store volume | APFS; device location `Internal`; solid state `Yes`; SMART `Verified` |
| At-rest observation | FileVault `Yes`; observation only, not an approved production at-rest profile |
| Power / sleep control | AC power; `/usr/bin/caffeinate -dimsu` wrapped the command |
| Rust | rustc 1.96.1 (`31fca3adb`, LLVM 22.1.2); cargo 1.96.1 |
| Build | Cargo `release`; exact feature `controlled-benchmark` |
| Available parallelism | 10 |
| Concurrent benchmark or Cargo work | none; benchmark workload concurrency 1 |

The benchmark creates coordinator and adapter roots beneath `std::env::temp_dir()`.
The storage qualification above therefore describes the volume that actually held the
two fresh SQLite stores for every repetition, not merely the repository volume. Native
temporary paths, device nodes, volume names, UUIDs and serial numbers are not retained.

## Executed protocol

The four release-profile example tests passed before the physical run: strict
`500`/`10000` CLI parsing, nearest-rank percentile calculation, pinned adapter-schema
digest and exactly one final-guard timer entry.

The measured command, wrapped only for AC-power sleep prevention and wall timing, was:

```shell
cd kernel
caffeinate -dimsu cargo run --locked --release \
  -p helix-coordinator-sqlite \
  --example durable_dispatch_benchmark \
  --features controlled-benchmark -- \
  --warmups 500 \
  --samples 10000 \
  --output ../specs/005-durable-dispatch/evidence/m4-raw.json
```

The measured interval starts at the first instruction of fixed-order final-guard
acquisition. It includes the production coordinator dispatch commit, durable handoff,
independent adapter receive and consume, signed receipt, and coordinator receipt commit;
it ends immediately after external validation that the effective state is `EXECUTING`.
One authentic PLAN-004 preparation and fresh coordinator/adapter roots are constructed
outside each repetition's measured interval. This remains a deterministic no-effect
adapter workload: `EXECUTING` does not mean a host mutation or successful effect.

| Workload property | Exact value |
|---|---:|
| Warmup operations | 500 |
| Measured operations / raw samples | 10,000 / 10,000 |
| Total unique operations | 10,500 |
| Committed `EXECUTING` receipts | 10,500 |
| Concurrency | 1 |
| Coordinator ordinary / control capacity | 1,024 / 32 |
| Adapter ordinary capacity | 1,024 |
| Queue depth at each new dispatch | 0 |
| Retained preparations / grants per fresh root | 1 / 1 |
| Grant lifetime | 5,000 ms |
| Raw sample order | execution order after warmup |

## Physical result

Percentiles were independently recomputed from the 10,000 retained nanosecond samples
with the same exact nearest-rank rule as the benchmark.

| Metric | Result | Reference limit | Status |
|---|---:|---:|---|
| p50 | 58,029,834 ns (58.029834 ms) | informational | recorded |
| p95 | 66,797,000 ns (66.797000 ms) | 50 ms | **miss** |
| p99 | 83,636,542 ns (83.636542 ms) | 100 ms | pass |
| maximum | 289,463,209 ns (289.463209 ms) | informational | recorded, not discarded |

SC-005 and `PERF-002` require both percentile limits. The p95 miss is blocking even
though p99 passed, all operations committed and no functional benchmark error occurred.
No second run replaced this artifact.

## Exact stores and inputs

Both runtime stores reported SQLite 3.53.2 with source ID
`2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.
The coordinator used application ID `1212962883`, schema version 2; the adapter used
application ID `1212962889`, schema version 1. Both exact profiles were:

- journal mode `wal`;
- `synchronous=2` (`FULL`);
- `wal_autocheckpoint=0`;
- `foreign_keys=1`, `trusted_schema=0`, `cell_size_check=1` and
  `recursive_triggers=1`;
- busy-wait bound 30,000 ms.

| Retained input or artifact | SHA-256 |
|---|---|
| Release executable | `1b90a1d9ca1ec0b7e7ec567147d636b51868bd9c410056cc8ebf4f7902a89dc6` |
| Benchmark source | `807bd706ec8bcc2ad8a08bb81008e24e5b79a223decec6e6072a719f84a90626` |
| `kernel/Cargo.lock` | `17b1355d76b855d5923b8223e58939dad1b6d76368d9aa1ae59046e8094b5c60` |
| Coordinator base schema V1 | `e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e` |
| Coordinator dispatch schema V2 | `ee05a9e4db7934ae6ba2be9536595c0b100fec7bc3d8991d884674aa1ceb2440` |
| Adapter inbox schema V1 | `f6d4917175038ff726ec6d27a1c59de7210f58a1079cf428586130862c050724` |
| 10,500 canonical benchmark plans | `cb3ad4bebabdef1afc6c47be918f78c23f4477e1a950e2834561cfc38d0bbeb6` |
| Contract cases | `70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a` |
| Expected outcomes | `8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4` |
| Fault-boundary fixture | `041c2eca7dfdc5b3c3a0a7b5a3d1399c26133f9fe63e8a26e23c9bc9bab7ef3b` |

The raw create-only artifact is
`specs/005-durable-dispatch/evidence/m4-raw.json`: 165,212 bytes, SHA-256
`fcf86188a41c49a4ef2def0116e614cde8125e5164be95f2a5916bfc94738983`.
It retains schema `helixos.durable-dispatch-benchmark/1`, acceptance reference
`PLAN-005-SC-005`, exact environment/store/workload metadata and all 10,000 samples.

## Independent validation and interpretation

The retained JSON was parsed and checked independently after exit 0. Validation proved:

- exact schema, acceptance reference and diagnostic claim fields;
- exact physical M4, RAM, macOS/build, architecture and APFS assurance fields;
- source, executable, Cargo.lock, schema and frozen corpus digests;
- exact WAL/FULL SQLite source/profile in both independent stores;
- 500 warmups, 10,000 positive raw samples, 10,500 unique operations and 10,500
  committed `EXECUTING` receipts;
- exact nearest-rank p50/p95/p99 and maximum recomputation; and
- no retained private user path, username, PAT marker, common cloud credential marker or
  private-key header.

The raw executable intentionally labels its own output `local-diagnostic`, with
`diagnostic_only=true`, `physical_m4_claim=false`,
`acceptance_gate_evaluated=false` and
`reference_limits_are_acceptance_verdict=false`. This wrapper records that the actual
host met the physical metadata precondition and evaluates the limits, but it does not
convert the working-tree run into immutable or self-attested release evidence.

T091 is complete as an honest physical diagnostic. `PERF-002`, aggregate PLAN-005
`claim_status`, exact-commit evidence, approved encrypted-at-rest qualification,
`F_FULLFSYNC`/power-loss durability, production supervisor/IPC/provider, physical
isolation, full-machine restore/activation and Tier 1 support all remain pending or out
of scope as declared in the catalogue.
