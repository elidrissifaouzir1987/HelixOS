# PLAN-003 first immutable CI remediation

**Recorded**: 2026-07-10
**Failed source commit**: `b63d0bd25f979117a807c1c8e399c291cea39563`
**Status**: locally remediated; T054 remains pending until an unchanged three-platform
run succeeds and publishes its artifacts and attestations

## Failed runs inspected

- Durable replay claim store:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29114609468`
- Portable signed contracts:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29114609485`
- Current plan eligibility passed unchanged:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29114609483`

The GitHub job logs were read directly. No failed run is represented as immutable
success evidence.

## Confirmed causes and bounded corrections

1. Linux and macOS exposed a real creator/waiter interposition in live-root role
   initialization. A creator could create the empty role file, lose the scheduler race
   before locking it, then reject the exact `LIVE_READY` role published by a waiter
   after that waiter consumed the intent. Locked finalization now accepts an exact role
   already published by another initializer, repairs only the exact empty live
   reservation and never overwrites an unknown role. Two deterministic unit regressions
   cover waiter-first publication and unknown-role preservation.
2. Windows checkout CRLF bytes made LF-only `include_str!` source guards fail. The
   initialization and portability tests now normalize CRLF to LF before their exact
   multiline assertions, with an explicit LF/CRLF regression. Production source and
   semantics are unchanged.
3. Historical `helixos-kernel` tests referenced Windows-only filesystem extensions on
   Unix. The Windows sharing-mode test is now Windows-gated; reparse-directory helpers
   retain the Windows implementation and use the standard Unix symlink API on Unix.
   Production code is unchanged.
4. A hosted Windows workspace run serialized 64 FULL-sync contenders beyond the
   fixture's five-second correctness window, so 62 calls honestly returned
   `Unavailable`. The test-only contention window is now 30 seconds. This does not
   change the production API or the separate 40 ms + 50 ms SC-004 deadline fixture.

## Local validation after remediation

- replay targeted default source/root tests: 33 passed, one private worker ignored;
- full replay all-target/all-feature suite: passed, including the 68-case corpus;
- exact workspace all-target/all-feature Clippy with `-D warnings`: passed;
- exact workspace all-target/all-feature tests with one test thread: passed;
- historical `helixos-kernel` Windows tests: 68 passed;
- release contention: 4 scenarios x 100 rounds x 64 threads plus 20 process rounds x 8
  contenders, exactly one durable winner per required key, passed in 76.07 seconds;
- release process-kill matrix: 6/6 parent matrices passed;
- targeted replay rustfmt and `git diff --check`: passed.

The Unix implementations and the creator/waiter ordering must still be confirmed by the
new Linux/macOS GitHub jobs. Hosted macOS evidence remains distinct from physical Mac
mini M4, `F_FULLFSYNC` and power-loss evidence.
