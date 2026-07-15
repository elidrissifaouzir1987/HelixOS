# PLAN-005 User Story 2 — Inbox Receipt and SC-001 Dispatch Contention

**Captured**: 2026-07-13

**Branch**: `codex/plan-005-durable-dispatch`

**Claim status**: `pending-evidence`

This local synthetic result closes the implementation evidence requested by T055. It
drives a genuine PLAN-004 preparation through the production V2 coordinator dispatch,
loads only the byte-identical retained `PENDING` outbox grant through read-only SQLite,
and calls the portable `receive_and_consume_exact_grant_v1` boundary backed by the
independent production adapter-inbox store. It proves one durable adapter receipt under
the exact SC-001 sequential, thread and process cardinalities. It does not claim T064
handoff, T052 coordinator receipt commit, a host effect, physical power-loss durability,
immutable CI, physical M4 performance, full-machine restore or Tier 1 readiness.

## Production path and custody boundary

- The preparation is the signed, committed PLAN-004 synthetic irreversible case. Its
  test-only media type is `text/markdown`, the strict type/subtype intersection accepted
  by both PLAN-004 and the PLAN-005 execution-grant contract. No production contract or
  validator was widened.
- `dispatch_prepared_once_v1` performs the real reload, two authority captures, fixed
  guard order, one consuming permit and V2 transaction. Preliminary and final captures
  use the same coherent monotonic sample because the production store requires the
  persisted sampled and grant-issued instants to be identical at this boundary.
- Test transport is deliberately read-only SQL. It proves one grant, record, transition
  and `PENDING` outbox member with no current delivery attempt, then authenticates and
  forwards the exact retained canonical grant bytes. It never updates delivery state.
- The local adapter wrapper verifies the input to recover its grant identity. On the
  hardened exact-duplicate fast path it ignores raw receipt storage and calls the T050
  `readback_grant_v1` boundary with the grant and receipt verification resolvers before
  returning retained state or retained receipt evidence. The grant resolver injected
  into the adapter owns only the public Ed25519 verification key; coordinator grant
  signing authority never crosses that seam.
- Receipt creation uses the production adapter receive and terminal transaction, an
  independent clock, supervisor-epoch and RUNNING-admission observation, domain-bound
  entropy, a provisioner-bound signing profile and a fixed public-synthetic Ed25519 key.
  Every positive result is decoded, signature-verified and rebound to the exact retained
  grant plus adapter-root identity.

## Exact ordinary matrices

All three release matrices are ordinary, non-ignored tests in
`kernel/helix-coordinator-sqlite/tests/dispatch_end_to_end_contention.rs`. Every
contender independently executes coordinator dispatch, read-only retained-grant load,
portable adapter receive/consume and receipt authentication. Coordinator and adapter
winners are counted as independent race axes; the test does not require the same
contender to win both.

| Matrix | Coordinator outcomes | Adapter outcomes | Exact retained result |
|---|---:|---:|---|
| 10,000 sequential calls | 1 committed, 9,999 prior-exact | 1 consumed, 9,999 retained receipt | one grant and byte-identical receipt |
| 100 rounds × 64 synchronized threads | per round 1 committed, 63 prior-exact; aggregate 100/6,300 | per round 1 consumed, 63 retained; aggregate 100/6,300 | one grant/receipt per fresh round |
| 20 rounds × 8 synchronized child processes | per round 1 committed, 7 prior-exact; aggregate 20/140 | per round 1 consumed, 7 retained; aggregate 20/140 | one grant/receipt per fresh round |

Every matrix explicitly counts zero denied, failed or ambiguous coordinator outcomes;
zero pre-receive or definite refusals; zero adapter conflicts, quarantines, unavailable,
unhealthy or not-reached paths; and exactly one `Consumed` return per operation. All
returned receipt bytes (or, across the bounded child protocol, their locally verified
canonical-byte SHA-256) are identical. Child processes wait at READY/GO before opening
either SQLite root and independently reconstruct both provisioner-attested identities.

The sequential matrix reuses one strict coordinator store and one adapter consumer per
half while preserving all 10,000 production calls and per-call verification. At the
midpoint it drops both, forces the last WAL anchors closed, strictly reopens and verifies
the retained receipt, then uses fresh handles for the second half. Thread and process
rounds use fresh roots and independently opened handles. Every round joins/exits all
contenders before the same last-close, strict-reopen and retained-receipt checkpoint.

## Durable cardinalities and no-effect statement

After each operation/round, read-only assertions prove:

| Root | Required exact graph |
|---|---|
| Coordinator V2 | 1 grant, 1 `DISPATCHING` record, 1 transition, 1 `PENDING` outbox, 0 delivery attempts, 0 coordinator receipts |
| Adapter inbox | 1 `CONSUMED` grant, 2 transitions, 1 consumed receipt, 2 adapter events, 0 conflicts, 0 quarantines |

This is a no-effect boundary. T051 deliberately exposes no effect handle, execution
token or host-mutation callback; T055 injects none. The coordinator remains
`DISPATCHING/PENDING`, delivery attempts and coordinator receipts remain absent, and the
adapter retains only its consumed decision and signed evidence. The zero-call sentinel
is supplementary; the structural API absence and durable/event counts are the evidence.
No target resource or operational effect outside the two evidence SQLite roots is
mutated. The only writes are the explicitly counted durable coordinator and adapter
records.

## Reproduction and measured local results

The exact commands below passed with the locked dependency graph on the local arm64
macOS host:

```sh
cd kernel

/usr/bin/time -p cargo test --locked -p helix-coordinator-sqlite \
  --test dispatch_end_to_end_contention \
  exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption \
  -- --exact --nocapture

/usr/bin/time -p cargo test --locked -p helix-coordinator-sqlite \
  --test dispatch_end_to_end_contention \
  exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round \
  -- --exact --nocapture

/usr/bin/time -p cargo test --locked -p helix-coordinator-sqlite \
  --test dispatch_end_to_end_contention \
  exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round \
  -- --exact --nocapture
```

Measured results:

| Command | Test time | Wall/user/system |
|---|---:|---:|
| 10,000 sequential | 362.90 s | 364.37 / 354.83 / 7.54 s |
| 100 × 64 threads | 380.64 s | 380.93 / 469.81 / 104.74 s |
| 20 × 8 processes | 16.56 s | 16.91 / 18.00 / 2.32 s |

Before the exact runs, reduced 10-call, 2×4-thread and 2×2-process versions passed
together. The one-operation production smoke including forced restart passed in 0.35 s.

## Supporting T039–T054 validation

The final locked validation also exercised the earlier User Story 2 contracts and
restart/readback paths:

| Scope | Final result |
|---|---:|
| `helix-dispatch-inbox-sqlite` package | 59 passed, 4 ignored |
| `helix-plan-dispatch` package | 45 passed, 0 ignored |
| coordinator `contract` | 22 passed |
| coordinator `dispatch` | 2 passed |
| coordinator `dispatch_commit` | 4 passed |
| coordinator `dispatch_migration` | 6 passed |
| coordinator `dispatch_receipt` | 4 passed |
| coordinator `dispatch_redaction` | 5 passed |
| coordinator `portability` | 8 passed |
| T055 production restart smoke | 1 passed |

The four ignored inbox-package cases are the standalone T041 release workloads. They
do not create an evidence gap for SC-001: the three complete coordinator-to-adapter
T055 matrices above execute the exact release cardinalities as ordinary non-ignored
tests. The public-only resolver hardening applied after the timed measurements changes
only test-fixture key custody, not the verification key or production path; format,
check, strict Clippy, the smoke and reduced versions of all three matrix shapes were
rerun afterward.

## Preserved boundaries and nonclaims

T055 stops after exactly one adapter consumption and retained adapter receipt. It does
not invoke transport handoff, mark coordinator outbox state `HANDED_OFF`, insert a
delivery attempt, or commit the adapter receipt into the coordinator. Those are separate
T064/T052 responsibilities. It does not promote the aggregate project or conformance
catalogue beyond `pending-evidence` and does not turn local wall-clock timings into the
declared physical performance evidence.

The 27 unrelated user-owned Rust paths recorded in the evidence baseline remained
outside this work. No file was staged, committed or pushed by this result.
