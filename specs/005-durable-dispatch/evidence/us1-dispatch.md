# PLAN-005 User Story 1 — Durable Dispatch MVP

**Captured**: 2026-07-13

**Branch**: `codex/plan-005-durable-dispatch`

**Claim status**: `pending-evidence`

This local result closes tasks T021–T038 for the coordinator-only no-effect MVP. It
proves a typed lookup-only orchestration path, exact V2 reload/migration boundaries,
one canonical signed-grant commit graph, exact uncertain-commit readback, and preserved
PLAN-001 through PLAN-004 tests. It does not prove adapter consumption, a transport
handoff, a host effect, power-loss durability, the complete SC-001 release matrix,
physical M4 performance, immutable CI, full-machine restore, or Tier 1.

## Implemented boundary

- `DispatchLookupRequestV1` is the only public request input. The coordinator reloads
  the complete current PLAN-004/V2 graph and classifies missing, torn, restored,
  failed, quarantined, prior-exact, conflicting, unavailable and unsupported state.
- `dispatch_prepared_once_v1` obtains effect/capacity projections only from the trusted
  reloaded store value, captures authority twice, preserves the PLAN-004 guard order,
  retains one consuming permit through the store closure and performs one exact
  readback after an uncertain commit. It never signs or commits again during readback.
- Attempt, grant and one-shot nonce identities use three domain-separated entropy
  requests. The exact canonical signed envelope uses the dedicated grant signer
  purpose/domain and a deadline bounded by all authority limits and 5,000 ms.
- `SqliteCoordinatorStoreV2::open_existing` admits only an already-published exact V2
  root. It neither initializes nor migrates V1, and the unchanged V1 opener refuses V2.
- Explicit V1-to-V2 migration remains crate-internal maintenance authority under the
  existing PAUSE/provider quiescence and verified-backup cut. The overlay, migration
  receipt and final `user_version=2` publication share one immediate transaction;
  uncertain completion is classified by exact receipt/schema readback.
- The initial dispatch transaction contains exactly comparison, grant, current record,
  transition, outbox, event and metadata members. Transport and signing are absent from
  the SQLite writer transaction. Grant/operation/nonce uniqueness and byte-identical
  outbox retention are enforced by the reviewed overlay and commit code.
- Once a dispatch overlay exists, the PLAN-004 known-before-dispatch failure/release
  path refuses to release reservation or recovery custody. Permanent dispatch events
  are internally exact, outwardly redacted, and metrics are bounded safe-integer
  counters without labels or payloads.

## Validation results

The final local commands completed successfully:

```sh
cd kernel
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --quiet
cargo test --locked -p helix-plan-dispatch \
  --test authority --test bounds --test guard --quiet
cargo test --locked -p helix-coordinator-sqlite \
  --test dispatch --test dispatch_commit --test dispatch_contention \
  --test dispatch_migration --quiet
cd ..
git diff --check
```

Focused final counts were:

- portable authority/bounds/guard integration: 9 passed;
- coordinator durable reload: 2 passed;
- coordinator canonical commit/readback: 4 passed;
- coordinator contention harness: 5 passed and 4 release workloads ignored;
- coordinator migration/restart/version boundary: 6 passed;
- coordinator library unit suite: 122 passed;
- complete locked workspace command: exit 0.

The public portable orchestrator also has a unit test that drives lookup → authority →
fixed guards → permit → exact store commit. The V2 migration suite reopens an exact V2
root through the public V2 type after restart, proves V2 open does not auto-migrate V1,
and confirms the old V1 type still refuses the resulting root.

## Preserved custody

The 27 unrelated user-owned Rust paths under `helixos-kernel`, `helixos-mcp-shim` and
`helixos-provision` remained outside PLAN-005. Their sorted path-list SHA-256 after the
final validation was:

```text
cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530
```

No file was staged, committed or pushed by this result.

## Nonclaims and deferred evidence

- The four ignored T025 release workloads retain the exact declared 10,000 duplicate,
  100 × 64-thread and 20 × 8-process cardinalities, but this local T038 pass did not run
  them as release evidence. The complete SC-001 claim additionally requires the future
  adapter-consumption boundary and therefore remains pending.
- The coordinator outbox is durable but not delivered in User Story 1. There is no
  adapter inbox, receipt, `EXECUTING` advance, real effect or execution-token API here.
- Process-kill, lost-acknowledgement, cross-store restore/removal, supply-chain,
  immutable hosted artifacts and physical M4 measurements belong to later PLAN-005
  tasks and remain `pending-evidence`.
