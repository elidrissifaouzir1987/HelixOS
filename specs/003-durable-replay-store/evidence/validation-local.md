# PLAN-003 local validation and removal evidence

**Recorded**: 2026-07-10
**Host**: Microsoft Windows 10.0.26200, x64
**Git base**: `6b31af88af28f4356517846acb9f3bb77a48fcf6`
**Worktree**: Feature 003 is uncommitted; this file is not immutable release evidence

## Feature 003 gates

Passing final gates:

- `cargo fmt -p helix-replay-sqlite -- --check`;
- strict package Clippy, default and `--all-targets --all-features -D warnings`;
- complete default and all-feature package suites;
- executable corpus: 68/68 real cases under `test-fault-injection`, zero blocked;
- default executable corpus: 47 public cases, with 21 crash/fault cases explicitly
  compiled out rather than simulated;
- backup/restore: 15 passed plus one private worker ignored, including real concurrent
  online backup, package verification, no-clobber reservation and pending activation;
- root safety: waiting writer, live-intent-only recovery and concurrent multi-process
  initialization; 20 repeated process rounds passed;
- release process-kill matrix: 6/6 parent groups, 18 frozen boundaries;
- release contention: 4 x 100 x 64 threads plus 20 x 8 processes;
- release benchmark example compiles. Its clean-worktree runtime guard was not bypassed,
  so no latency claim is made from this uncommitted tree.

## Workspace gates

- `cargo test --locked --workspace --all-targets -- --test-threads=1`: pass.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: pass.
- `cargo fmt --all -- --check`: fail due to pre-existing formatting debt in exactly
  `helixos-kernel`, `helixos-mcp-shim` and `helixos-provision`. Feature 003's package
  format check passes, and unrelated legacy files were not rewritten.

The feature-002 inverse-dependency source gate was updated from “no consumers” to one
closed reviewed consumer: `helix-replay-sqlite`, which implements `ReplayClaimantV1`
but is not a host-effect adapter.

## Removal/isolation drill

Commands:

```text
cargo tree --locked --workspace --invert helix-replay-sqlite --edges normal
cargo test --locked --workspace --exclude helix-replay-sqlite --all-targets --all-features -- --test-threads=1
```

Both passed. The inverse tree contains only `helix-replay-sqlite`; no workspace package
depends on it. Excluding the crate leaves features 001/002 and the legacy workspace
green. Any in-memory replay claimant remains test-only; production has no silent
fallback from a failed durable store.

## Reviewed hashes

| Artifact | SHA-256 |
|---|---|
| `kernel/Cargo.lock` | `f3b6c0cb07f9e9ddec2f6b64cb3b00f7df99fd93066315e92f1a5dfa4b3498f8` |
| replay schema v1 | `7749bd426803f589c6a4dd0643d0b19d76aa38bc0645bc74db205f24e687d53d` |
| backup manifest schema v1 | `ecd2a0ddfbd0fc3e64f9a9bd2ea7659adef04bfd551c7c49bf3fceb51f3255b6` |
| 68-case corpus | `7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff` |
| expected outcomes | `687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac` |

At the time of this pre-commit record, the clean controlled local-SSD benchmark was
still pending. It was later completed against commit
`c7f736656b572a88c8b805a34c5efa872834c56d`; see
`benchmark-local-c7f736656b572a88c8b805a34c5efa872834c56d.md`. Still pending: one
immutable commit across Linux x64, macOS arm64 and Windows x64 with attestations and
preserved artifacts; controlled Mac mini M4 benchmark evidence; and the separately
scoped `F_FULLFSYNC`/power-cut investigation.
