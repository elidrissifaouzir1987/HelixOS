# PLAN-004 hosted Windows process-kill reachability remediation

**Status**: local correction validated; hosted rerun pending
**Date**: 2026-07-12

This record is diagnostic and remediation evidence only. It is not an immutable
PLAN-004 artifact, production restore evidence, power-loss evidence or a Tier 1 claim.

## Failed hosted observation

- Workflow: `Durable preparation before dispatch`
- Run: [29192810088](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29192810088)
- Event: pull request
- Exact source: `b3132586245acea415104381b337d3fea3303444`
- Windows job: [86650389938](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29192810088/job/86650389938)
- Result: macOS arm64, Linux x86_64 and the path/LF policy job passed; the Windows job
  passed formatting, strict lint, prerequisite contracts, hosted coordinator tests,
  corpus/digest checks, provenance/production backup-restore tests and release
  contention before failing only in the release process-kill step.

The Windows release parent completed the four private child-entry tests, then failed
after 42.02 seconds because the selected child exited before
`restore_empty_coordinator_root_reserved#1`. The prior
`restore_package_and_pinned_provenance_accepted#1` selection could be reached only
because the hidden conformance driver calls the private probe-bearing acceptance helper;
that helper is not the public Windows production entry.

## Contract diagnosis

The authoritative v1 contract requires Windows clean-root restore acceptance to return
`RESTORE_PLATFORM_UNSUPPORTED` before package capture, trust custody, PAUSE acquisition
or destination mutation. The production acceptance wrapper and its defensive restore
gate both preserve that refusal. Therefore none of the 14 frozen `restore` boundary IDs
is reachable through the public Windows production contract.

The frozen corpus is still exact and unchanged:

- 123 distinct boundary IDs;
- 167 controlled process-kill cases;
- 14 `restore` boundary IDs;
- 17 `restore` cases, because `restore_recovery_package_imported` expands to four
  occurrences; and
- 150 production-reachable Windows process-kill cases.

This was a test-oracle reachability mismatch, not a production-state, SQLite durability
or restore-refusal failure. Weakening the Windows refusal or deleting frozen corpus
entries would violate the reviewed platform contract.

## Correction

`kernel/helix-coordinator-sqlite/tests/process_crash.rs` now keeps the original
123-boundary/167-case registry and router assertions, defines the exact 14-ID Windows
unreachable set, and validates the host partition independently. The ignored release
executor runs all 167 cases on macOS/Linux and exactly 150 cases on Windows. The public
runtime refusal remains covered by `production_restore_conformance.rs`; the source-order
proof that it precedes capture, trust, PAUSE and mutation remains covered by
`restore_maintenance_api.rs`.

## Local validation

From `kernel/` with the pinned Rust/Cargo 1.96.1 toolchain and committed lockfile:

- tests-first RED: the new partition test failed to compile until the reachability
  predicate existed (`E0425`);
- exact partition test: 1 passed;
- ordinary `process_crash` target with all features: 78 passed, 5 ignored;
- exact ignored release process-kill parent on macOS arm64: 1 passed in 16.86 seconds,
  retaining all 167 cases; and
- production restore platform-contract oracle: 1 passed;
- source-order no-capture/no-mutation and public-surface oracle: 3 passed;
- package formatting check and strict all-target/all-feature Clippy: passed; and
- hosted Windows rerun: pending a committed source revision.

## Evidence boundary

The correction establishes only that the release harness follows the already reviewed
platform contract while preserving the full frozen inventory and exhaustive
non-Windows execution. It does not add Windows clean-root restore support, qualify the
synthetic provider for production, prove power-loss behavior, replace the physical-M4
artifact, close pending SBOM/advisory/attestation fields or change the PLAN-004
`pending-evidence` claim status.
