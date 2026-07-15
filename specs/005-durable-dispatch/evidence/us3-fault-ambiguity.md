# PLAN-005 User Story 3 — Fault and Handoff Ambiguity

**Captured**: 2026-07-13

**Updated**: 2026-07-14

**Branch**: `codex/plan-005-durable-dispatch`

**Claim status**: `complete for the local T070 synthetic in-process/process-kill, lost-ack, and flood scope; physical power loss NOT TESTED`

This record closes T070 without broadening the claim. The frozen PLAN-005 registry has
exactly 90 ordered boundaries. Its fixture declares two distinct cases for every
boundary—one `in-process` and one `process-kill`—for exactly 180 cases. Every one of
those 180 mode-specific cases now runs through its real production workflow, injects
at the selected production checkpoint exactly once, and is classified by authoritative
durable readback.

The compiled selector-only test remains useful structural evidence, but it is not
counted as a workflow case. Likewise, supplemental adapter PAUSED scenarios are not
counted twice.

## Closed corpus and exact ownership partition

| Driver | Exact boundary IDs | In-process cases | Process-kill cases | Declared total |
|---|---|---:|---:|---:|
| Coordinator dispatch/handoff/readback | FB001–FB022 and FB040–FB071 | 54 | 54 | 108 |
| Adapter inbox | FB023–FB039 | 17 | 17 | 34 |
| Migration/backup/restore lifecycle | FB072–FB090 | 19 | 19 | 38 |
| **Closed total** | **FB001–FB090** | **90** | **90** | **180** |

FB039 belongs only to the adapter retained-receipt readback path. It is absent from the
coordinator partition. The adapter process-kill release gate runs 26 subprocess
scenarios: the 17 primary Running scenarios correspond to the 17 declared adapter
cases, while nine additional PAUSED terminal scenarios are supplementary coverage.

`frozen_primary_ledger_is_exactly_90_boundaries_and_180_unique_cases` proves that the
authoritative registry and fixture contain the exact ordered 90/180 cardinality,
unique `PLAN005-FB-NNN::mode` case IDs, one selected boundary, and expected reach and
injection counts of one. The six real release gates below prove the corresponding
production workflow executions; the ledger test alone is not used as runtime evidence.

## Durable reopen oracle for FB001–FB071

| Fault interval | Required state after strict reopen |
|---|---|
| FB001–FB016 | Base operation remains `PREPARING`; no deliverable grant exists |
| FB017–FB021 | Coordinator retains the one exact `DISPATCHING` grant/outbox authority |
| FB022 | The same dispatch remains in receipt recovery or explicit unknown custody |
| FB023–FB029 | Adapter grant is absent because the receive transaction did not commit |
| FB030 | Adapter retains the exact `RECEIVED` grant |
| FB031–FB037 | Adapter remains exactly `RECEIVED`; the terminal transaction rolled back |
| FB038–FB039 | Adapter retains one exact closed receipt and performs no second consumption |
| FB040–FB043 | Coordinator remains `DISPATCHING`; receipt recovery or unknown custody is required |
| FB044–FB051 | Consumed closure did not commit; coordinator remains in recoverable dispatch custody |
| FB052 | Coordinator retains `EXECUTING` with the exact consumed receipt |
| FB053–FB070 | Refusal closure did not commit; reservation remains held and the receipt is recoverable |
| FB071 | Coordinator retains `FAILED`, the exact refusal evidence, and one reservation release |

## Durable reopen oracle for FB072–FB090

| Fault interval | Required state after strict reopen |
|---|---|
| FB072–FB075 | Migration transaction rolled back to strict V1, `user_version = 1`, with no dispatch overlay |
| FB076 | Strict V2 with exactly one bound migration receipt |
| FB077 | No coordinator/adapter backup component or terminal index is published |
| FB078 | Verified coordinator component only; no adapter component or terminal index |
| FB079–FB082 | Both verified components exist, no terminal index is visible, and the incomplete package is rejected |
| FB083 | Both components plus the signed manifest-last index form one accepted package with exact cross-store inventory |
| FB084 | Both restore roots remain empty and no PAUSE/rotation authority file exists |
| FB085 | Both roots remain empty; one canonical attempt-bound PAUSE/rotation authority is durable |
| FB086 | Coordinator copy is `INITIALIZING`; adapter root remains empty; PAUSE authority remains active |
| FB087 | Both copies are `INITIALIZING`; neither is activated or deliverable |
| FB088–FB090 | Both stores strictly reopen as structurally complete `RESTORE_PENDING` copies under the canonical PAUSE authority; neither is activated or deliverable |

After that non-mutating reopen succeeds, a separately authorized recovery phase proves
the PAUSED result, zero automatic redelivery, exact expired-grant/possible-consumption
quarantine evidence, zero consumption, and field-identical typed evidence across two
idempotent retries for FB084–FB090. Those recovery assertions are not mislabelled as
part of the initial strict-reopen oracle.

The migration registry order is a catalogue order, not a false SQL execution order.
The real temporal sequence is FB073 immediately after the already-held
`BEGIN IMMEDIATE`, then fresh backup verification and FB072, then FB074, FB075,
commit, and FB076. Every checkpoint remains immediately after its named event.

FB084 is the last checkpoint before any replacement identity or PAUSE/rotation record
is persisted. FB085 is reached only after the complete authority is durable. All new
root, boot, instance, supervisor identities, epochs, and generations are derived with
separate domains from the full accepted restore attempt. Strict readback recomputes
that authority and requires exact typed equality. Tests reject canonical
substitution of each of the five new identities and reject non-canonical JSON.

## Measured exhaustive fault results

All commands were run from `kernel/` with the locked dependency graph and the private
`test-fault-injection` feature.

| Real release gate | Result | Measured test time |
|---|---:|---:|
| Coordinator in-process, FB001–FB022 + FB040–FB071 | **PASS — 54/54 unique declared cases** | 14.58 s |
| Adapter in-process, FB023–FB039 | **PASS — 17/17 unique declared cases** | 0.81 s |
| Lifecycle in-process, FB072–FB090 | **PASS — 19/19 unique declared cases** | 26.00 s |
| Coordinator process-kill, FB001–FB022 + FB040–FB071 | **PASS — 54/54 unique declared cases** | 16.28 s |
| Adapter process-kill, FB023–FB039 | **PASS — 17/17 unique declared cases; 26 scenarios including nine supplemental PAUSED cases** | 1.62 s |
| Lifecycle process-kill, FB072–FB090 | **PASS — 19/19 unique declared cases** | 25.73 s |
| **Exhaustive total** | **PASS — 90/90 in-process + 90/90 process-kill = 180/180** | — |

The exact release commands were:

```sh
cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --test dispatch_faults \
  release_in_process_coordinator_handoff_and_readback_matrix \
  -- --exact --ignored --nocapture --test-threads=1

cargo test --locked -p helix-dispatch-inbox-sqlite \
  --features test-fault-injection --test process_crash \
  release_adapter_in_process_matrix_reopens_to_one_closed_state \
  -- --exact --ignored --nocapture --test-threads=1

cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --test dispatch_maintenance_faults \
  release_dispatch_lifecycle_in_process_matrix \
  -- --exact --ignored --nocapture --test-threads=1

cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --test dispatch_faults \
  release_process_kill_coordinator_handoff_and_readback_matrix \
  -- --exact --ignored --nocapture --test-threads=1

cargo test --locked -p helix-dispatch-inbox-sqlite \
  --features test-fault-injection --test process_crash \
  release_adapter_process_kill_matrix_reopens_to_one_closed_state \
  -- --exact --ignored --nocapture --test-threads=1

cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --test dispatch_maintenance_faults \
  release_dispatch_lifecycle_process_kill_matrix \
  -- --exact --ignored --nocapture --test-threads=1
```

For in-process cases, the explicit caller-owned selector is installed in
`InProcess` mode on the real store or portable production workflow. Each gate asserts
that the selected one-shot probe injected, drops live custody, strictly reopens the
durable root, and applies the closed oracle. Pre-publication injections stop with a
closed error. FB083 is the intentional irreversible exception: its checkpoint is after
the signed index was published last, so the injected post-publication signal may be
ignored and the backup may return success; strict readback must then accept exactly that
complete package.

For process-kill cases, the parent and child synchronize with a private READY/GO
protocol and terminate only after the selected production process barrier reports the
exact boundary. The coordinator child prepares its workflow before READY. The adapter
parent pre-seeds the exact durable fixture; after GO, the child strictly reopens it,
installs the selector, and executes the real adapter workflow. The parent then
terminates and reaps the fault child. Coordinator and lifecycle classification runs in
a separate strict-reopen child, while the adapter parent performs the strict reopen and
classification after reap. Restore cases additionally run idempotent recovery in a
third child only after the non-mutating reopen child succeeds. The snapshot
non-mutation test specifically covers the FB084/FB085 strict readbacks and their roots
and authority file.

## Lost-acknowledgement, migration, and flood gates

| Gate | Measured result |
|---|---|
| Portable ambiguity/conformance/control/reconciliation targets | **PASS — 18 tests** |
| Coordinator fault/readback/receipt/queue/migration ordinary targets | **PASS — 78 tests, 7 release/private tests ignored** |
| Adapter crash/readback/queue ordinary targets | **PASS — 12 tests, 4 release/private tests ignored** |
| Lifecycle ordinary target, including three new negative authority/readback tests | **PASS — 30 tests, 7 release/private tests ignored** |
| Coordinator 100-trial queue/control release gate | **PASS — 1 gate, 0.25 s** |
| Adapter 100-trial saturation/flood release gate | **PASS — 1 gate, 0.25 s** |
| Coordinator and adapter default checks, feature/all-target Clippy with `-D warnings`, rustfmt, and `git diff --check` | **PASS** |

The ordinary ambiguity and readback tests cover lost receive/consume acknowledgement,
byte-identical retained grants and receipts, post-expiry receipt evidence without
authority renewal, the exact 0/25/75/175 ms backoffs, four-observation limit, 500 ms
hard budget, and one transition into unknown/reconciliation custody on exhaustion.

Both queue release gates exercise 100 trials with ordinary capacity 1,024, reserved
control capacity 32, a 10,000-request exact-duplicate flood, at most 50 ms ordinary
backpressure, and at most 100 ms control p99. They passed without creating duplicate
dispatch work or borrowing control capacity.

The real migration target also passed all 12 tests, including the exact FB072–FB076
workflow and strict V1/V2 reopen classifications.

## Registry-placement corrections retained by this result

1. FB039 is adapter-owned only; the former duplicate coordinator readback call site
   and selector member remain removed.
2. FB044–FB052 stay immediately after their named mutations. Their real SQL order is
   044, 045, 049, 046, 048, 047, 050, 051, 052 because current-record projection must
   precede the append-only transition and the normative receipt flow is transition,
   outbox acknowledgement, then redacted event.
3. FB060 and FB061 use separate exact verifiers. FB068 remains immediately after the
   final `dispatch_records` mutation and before transition/event/outbox checkpoints.
4. FB084 and FB085 are now distinct pre-authority and post-authority windows. The
   attempt-bound canonical authority rejects identity substitution, and readback is
   separated from mutating retry/recovery.

## Process-kill versus power-loss limits

The local process-kill driver terminates a process only after a user-space production
checkpoint reports that it was reached. It tests SQLite transaction rollback versus
committed readback, strict reopen, idempotence, custody classification, and zero-effect
recovery for this subsystem. It does not cut machine power, bypass the operating-system
page cache, measure storage-controller flush behavior, validate filesystem/device write
barriers, exercise a production supervisor/provider, or prove full-machine activation
and restore.

Consequently, the green 180-case matrix is synthetic local no-effect evidence only.
It is not physical power-loss durability, physical isolation, full-machine restore,
Tier 1 readiness, or permission to dispatch a host effect. Aggregate claims that need
those external or physical gates remain `pending-evidence`.

No file was staged, committed, or pushed by this evidence update.
