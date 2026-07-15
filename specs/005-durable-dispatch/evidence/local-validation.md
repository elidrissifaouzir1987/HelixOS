# PLAN-005 Local Working-Tree Validation

**Captured**: 2026-07-14

**Baseline HEAD**: `6f8dfdd5194792e8592cd10ebaaf8828833effbe`

**Branch**: `codex/plan-005-durable-dispatch`

**Evidence class**: retained historical local validation snapshot based on the baseline
HEAD above; not an exact clean-commit result and not immutable release evidence

**Snapshot status**: captured before T095/T096. Schema digests, test totals and roadmap
counts below describe the bytes validated at capture time, not the later working tree.
Current lifecycle-restore results are recorded in `us4-restore-removal.md`.

This record contains no native test paths, user identifiers, credentials, private key
material, execution tokens, provider bindings or private canonical payloads. The tested
source included uncommitted PLAN-005 work. Therefore the results below establish local
subsystem behavior only; they do not bind an immutable commit or replace the unchanged
three-host workflow required by T094.

## Environment and reviewed inputs

| Item | Captured value |
|---|---|
| Hardware | Mac mini, Apple M4, model `Mac16,10`, 16 GB RAM |
| OS | macOS `26.5.2`, build `25F84`, `arm64` |
| Rust | `1.96.1 (31fca3adb 2026-06-26)`, host `aarch64-apple-darwin`, LLVM `22.1.2` |
| Cargo | `1.96.1 (356927216 2026-06-26)` |
| `kernel/Cargo.lock` SHA-256 | `17b1355d76b855d5923b8223e58939dad1b6d76368d9aa1ae59046e8094b5c60` |
| Workflow SHA-256 | `df8ae870c824f5d1ca00256654546017cf47f7de737c928a9e9ff9d9da4a1ef8` |
| Actionlint | `1.7.12`, Darwin arm64 binary SHA-256 `8db11704dc296f096216db4db65d86cd7f0ebfdf4c38453a1da276b137b88388` |

The hardware identity is environment metadata, not the physical performance evidence
required by T091. No benchmark threshold is claimed in this record.

## Protected unrelated working-tree changes

The 27 pre-existing changed Rust paths under `helixos-kernel`, `helixos-mcp-shim` and
`helixos-provision/src/main.rs` were excluded from every PLAN-005 edit. Their sorted
path-list SHA-256 remained
`cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530`
with count `27`. They were not formatted, staged, committed or rewritten.

## Final Rust command results

All commands below ran from `kernel/` with the pinned toolchain. Elapsed values are
local observations only. The two broad focused suites overlapped during orchestration;
their functional exit results are retained, but their elapsed times are not performance
evidence.

| Exact command | Final result |
|---|---|
| `cargo fmt --all -- --check` | exit 0; 1.532 s total |
| `cargo check --locked --workspace --all-targets` | exit 0; 11.56 s Cargo / 11.613 s total |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | exit 0; 13.61 s Cargo / 13.697 s total; zero warnings |
| `cargo test --locked --workspace -- --test-threads=1 --skip exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption --skip exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round --skip exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round` | exit 0; 148.70 s total; all default workspace targets and doctests passed |
| `cargo test --locked --package helix-dispatch-contracts --package helix-plan-dispatch --package helix-dispatch-inbox-sqlite --all-targets --all-features -- --test-threads=1` | exit 0; 118.33 s total |
| `cargo test --locked --package helix-coordinator-sqlite --all-targets --all-features -- --test-threads=1 --skip held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later --skip exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption --skip exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round --skip exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round` | exit 0; 165.91 s total |
| `cargo run --locked --package helix-coordinator-sqlite --features test-fault-injection --example durable_dispatch_corpus -- ../contracts/fixtures/durable-dispatch-v1/cases.json ../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json` | exit 0; 143 contract cases and 6 no-effect subsystem scenarios; summary SHA-256 `11341e7c2b0a840d020947111ca0892046f23ca4c799c83b432800224fee99f7`; 9.811 s total |

The focused all-feature coordinator command intentionally excludes the controlled
PLAN-004 hosted timing oracle
`held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later`, owned by
`PLAN-004-T043-SC-010-controlled-target`. The default-feature workspace run did execute
that ordinary local test successfully. This exclusion is not a claim that the hosted
timing gate has been reproduced locally.

## Exact end-to-end one-shot gates

| Exact filtered command | Result |
|---|---|
| `cargo test --locked --package helix-coordinator-sqlite --test dispatch_end_to_end_contention exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption -- --exact --nocapture --test-threads=1` | 1 passed, 0 failed, 23 filtered; 349.27 s test / 351.45 s total |
| `cargo test --locked --package helix-coordinator-sqlite --test dispatch_end_to_end_contention exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round -- --exact --nocapture --test-threads=1` | 1 passed, 0 failed, 23 filtered; 393.85 s test |
| `cargo test --locked --package helix-coordinator-sqlite --test dispatch_end_to_end_contention exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round -- --exact --nocapture --test-threads=1` | 1 passed, 0 failed, 23 filtered; 13.58 s test / 13.678 s total |

These gates retained exactly one dispatch and one adapter consumption for every
declared duplicate, thread round and process round, followed by strict last-close
reopen verification.

## Explicit ignored release gates

Every required public ignored gate was selected by exact name. Private child entry
points and older component-only PLAN-004 release gates were not selected.

| Exact command after `cargo test --locked` | Result |
|---|---|
| `--package helix-dispatch-contracts --test property release_100_000_generated_mutations_follow_closed_oracle -- --exact --ignored --nocapture --test-threads=1` | 1 passed; exactly 100,000 cases, 50,000 grants, 50,000 receipts, 26 families; deterministic seed `0x504c414e30303583`; 61.31 s |
| `--package helix-coordinator-sqlite --features test-fault-injection --test dispatch_faults release_in_process_coordinator_handoff_and_readback_matrix -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 14.61 s |
| `--package helix-dispatch-inbox-sqlite --features test-fault-injection --test process_crash release_adapter_in_process_matrix_reopens_to_one_closed_state -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 0.74 s |
| `--package helix-coordinator-sqlite --features test-fault-injection --test dispatch_maintenance_faults release_dispatch_lifecycle_in_process_matrix -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 25.94 s |
| `--package helix-coordinator-sqlite --features test-fault-injection --test dispatch_faults release_process_kill_coordinator_handoff_and_readback_matrix -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 16.12 s |
| `--package helix-dispatch-inbox-sqlite --features test-fault-injection --test process_crash release_adapter_process_kill_matrix_reopens_to_one_closed_state -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 1.34 s |
| `--package helix-coordinator-sqlite --features test-fault-injection --test dispatch_maintenance_faults release_dispatch_lifecycle_process_kill_matrix -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 25.66 s |
| `--release --package helix-coordinator-sqlite --test dispatch_queue_control release_coordinator_queue_control_profile_cardinalities -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 0.03 s test / 6.285 s total |
| `--release --package helix-dispatch-inbox-sqlite --test queue_control release_adapter_saturation_and_control_latency_profile -- --exact --ignored --nocapture --test-threads=1` | 1 passed; 0.03 s test / 6.787 s total |

The registry declares 90 ordered boundary IDs in two modes, hence 180 logical cases.
That number is not the raw process count: the three process-kill drivers execute 99
concrete iterations (54 coordinator, 26 adapter variants over 17 adapter IDs, and 19
lifecycle iterations).

## JSON, SQL, workflow and tool controls

Nine reviewed JSON files parsed successfully with `python3 -m json.tool`: four contract
documents, four frozen fixture documents and the removal-protected manifest.

| Reviewed JSON | SHA-256 |
|---|---|
| `contracts/dispatch-backup-manifest-v1.schema.json` | `ae7d12714aa995dc8779aaba29da268259ba1783dfa2e16a9385f7eed03daa67` |
| `contracts/execution-grant-v1.schema.json` | `f326cacda2a4fca49dc3278e758ed56ef178fef63cad9ff37eb0f506db6f021a` |
| `contracts/execution-receipt-v1.schema.json` | `d112c63c236df12004f9ef85fc4dd1e69443cc68044f42640dcaa6dba4f901e3` |
| `contracts/fault-boundaries-v1.json` | `afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26` |
| `fixtures/cases.json` | `70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a` |
| `fixtures/end-to-end-cases.json` | `d075223c2bbf58f0e434796f5aa44058c73f826de7ecec895330f690377bb44c` |
| `fixtures/expected-outcomes.json` | `8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4` |
| `fixtures/fault-boundaries.json` | `041c2eca7dfdc5b3c3a0a7b5a3d1399c26133f9fe63e8a26e23c9bc9bab7ef3b` |
| `evidence/removal-protected-files.json` | `d567c741c3e74e62a950d5c88e5ebb2540d0f3e957ed9fee7eadd9ee7a2014bb` |

SQL was loaded into fresh in-memory SQLite stores with `.bail on`:

| SQL control | Result |
|---|---|
| Adapter inbox V1 | 47 reviewed objects, `PRAGMA user_version = 1`, 0 foreign-key violations; SQL SHA-256 `f6d4917175038ff726ec6d27a1c59de7210f58a1079cf428586130862c050724` |
| PLAN-004 coordinator base plus PLAN-005 overlay (captured pre-T096) | 136 reviewed objects, `PRAGMA user_version = 2`, 0 foreign-key violations; overlay SHA-256 `ee05a9e4db7934ae6ba2be9536595c0b100fec7bc3d8991d884674aa1ceb2440` |

Additional controls:

| Command/control | Result |
|---|---|
| `python3 -m unittest discover -s tools/tests -p 'test_plan004_evidence.py' -v` | 19/19 passed |
| `python3 -m unittest discover -s tools/tests -p 'test_plan005_evidence.py' -v` | 36/36 passed |
| `actionlint -format '{{json .}}' .github/workflows/durable-dispatch.yml` | exit 0; exact output `[]` |
| unresolved SpecKit template scan excluding `quickstart.md` | no matches; `rg` exit 1 as expected |
| CRLF scan over PLAN-005 fixtures/spec/workflow/tools | no matches; `rg` exit 1 as expected |
| `python3 -m py_compile` for roadmap, PLAN-004 and PLAN-005 removal/supply tools | exit 0; cache redirected outside the repository |
| `python3 tools/update_roadmap.py --check` | captured exit 0 after T090 regeneration; PLAN-005 90/94 (95.7%), global 311/315 (98.7%), next focus T091 |
| `git diff --check` | exit 0 after evidence and roadmap regeneration |

Reviewed PLAN-005 tool SHA-256 values:

| Tool | SHA-256 |
|---|---|
| `tools/plan005_removal_drill.py` | `a8c202a51f4b29ad64848720614f094a9d31136a9761184c05fc22c60078bc4b` |
| `tools/plan005_supply_chain.py` | `31b9a81f4d119022accc9615fb158dde3d92951aa50296cfb6cb9768ebee0864` |
| `tools/tests/test_plan005_evidence.py` | `367ed27cfbe12e12979e0265b3fdb7628664d6108cf7c3bca613ab15ed95de87` |

## Diagnostic failures retained and corrected

The first unfiltered workspace attempt ran the three large end-to-end tests in one test
binary concurrently. The 10,000-duplicate test passed, but the 100-by-64 test returned
three fail-closed `ROOT_BUSY` refusals while 64 workers simultaneously performed strict
root open and full verification; the binary stopped after 357.12 s. The production
lease behavior was correct. The harness was corrected to pre-open independent stores
sequentially, retain the idle WAL anchors through the synchronized wave and perform a
genuine last close immediately before restart verification. The corrected exact 100-by-
64 gate then passed in 393.85 s. No production deadline, root lease or refusal behavior
was weakened.

Subsequent workspace passes exposed stale source guards rather than runtime defects:

- the coordinator's production dependency set now correctly includes the adapter inbox;
- the synthetic DELETE-journal fixture now uses checked PRAGMA update/readback;
- platform-specific directory synchronization delegates to the existing filesystem
  identity boundary;
- the restore maintenance exports are one closed public block; and
- the portable removal-manifest digest is repinned to the authoritative `d567...`
  manifest that includes the maintenance-fault test.

The first final PLAN-005 Python-tool run also rejected a newly generated Graphify memory
filename because it lacked a PLAN-005 identity. The file was renamed with `plan_005` in
its filename without changing its content or weakening the removal classifier; the
complete 36-test tool suite then passed.

## Interpretation and nonclaims

The local results support the synthetic durable one-shot dispatch subsystem, its closed
grant/receipt contracts, migration and paused clean-restore behavior, deterministic
fault handling, backpressure and local restart semantics. They do not establish:

- a host effect, execution token or sealed effect-handoff authority;
- physical power-loss, torn-sector or secure-erasure durability;
- an approved at-rest encryption profile;
- production supervisor, IPC, provider, effect adapter or physical isolation;
- physical Mac mini M4 latency thresholds;
- full-machine restore, activation or revival of prior authority;
- an unchanged Linux x64/macOS arm64/Windows x64 exact-commit result;
- immutable artifact preservation, SBOM/RustSec/license attestations or release
  provenance; or
- Tier 1 readiness or approval.

Accordingly, `claim_status` remains `pending-evidence`. T091, T092, T093 and T094 remain
separate gates; this local record must not be promoted to immutable release evidence.
