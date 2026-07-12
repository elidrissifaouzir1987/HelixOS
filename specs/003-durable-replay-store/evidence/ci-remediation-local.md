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

## First remediation rerun inspected

**Source commit**: `6e3940d40b5661ece7b4ed53ce9e7c8f598e4ff2`
**Status**: macOS corrections confirmed; two additional bounded races/fixture limits
remediated locally; T054 remains pending

- Durable replay claim store:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29117243288`
  - macOS arm64 passed the complete job;
  - Linux x64 failed only
    `concurrent_initializers_converge_when_one_process_is_killed` with
    `LOCATION_NOT_DEDICATED`;
  - Windows x64 failed only
    `concurrent_empty_root_initializers_converge_on_one_complete_schema`.
- Portable signed contracts:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29117243631`
  - Linux x64 and macOS arm64 passed;
  - Windows x64 repeated the same concurrent-schema test failure.
- Current plan eligibility passed unchanged on all three hosts:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29117243302`.

The Linux logs exposed two pre-lock time-of-check/time-of-use variants left outside the
first creator/waiter fix. A process could sample the role as absent, then reject the
intent after another process published that role; or it could observe `ensure_empty`
failure, then reject a consumed intent without rechecking the now-published role.
Intent-only inspection now precedes a final monotonic role-path sample, including the
inspection-error path. The original error is retained when no role was published. Two
deterministic regressions cover the false and error resolutions, and the process-kill
test passed 30 consecutive local repetitions.

The Windows logs predated diagnostic error-code preservation, so the exact public code
was masked by the fixture's generic panic. Code-path review showed that eight initializers
shared the per-process setup gate with only a 250 ms test budget while the hosted runner
executed the corruption suite in parallel. The convergence-only fixture now supplies
5,000 ms and renders the payload-free public error code on future failure. Production
setup-gate limits, SQLite deadlines and SC-004 are unchanged.

After these changes, strict all-feature package Clippy, the default all-target package
suite, the serialized all-target/all-feature package suite, 4/4 deterministic root
unit regressions, 3/3 root process tests and the 15/15 parallel schema-corruption binary
all pass locally. The release contention gate also passed 4 scenarios x 100 rounds x 64
threads plus 20 process rounds x 8 contenders with exactly one durable winner in 73.87
seconds, and the release process-kill matrix passed 6/6. Cross-host confirmation still
requires a new immutable CI commit.

## Second remediation rerun inspected

**Source commit**: `d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3`

- Durable replay claim store passed unchanged on Linux x64, macOS arm64 and Windows x64:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798`.
  Its artifacts and attestations are catalogued separately, completing T054.
- Current plan eligibility passed unchanged on all three hosts:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903780`.
- Portable signed contracts passed on Linux and macOS, but Windows failed only after all
  workspace tests, when the PLAN-001 generator rewrote the intentional trailing-LF
  negative wire fixture:
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903784`.

The committed fixture and Rust generator both contain exactly one final LF byte. With no
path attribute, Windows checkout converted that byte to CRLF, and the byte-exact
generator restored LF, producing false drift. A targeted `text eol=lf` attribute now
pins that fixture's checkout bytes without changing its wire, generator or validation
semantics. A forced checkout under the Windows `core.autocrlf=true` configuration
produced 2,103 bytes ending in LF, and the exact generator drift command stayed clean.

## Later hosted setup-gate starvation finding

**Observed source commits**: `2a802692df4d255fc3877dcdf5389728357c9fff` and
`cdf69dd6c6014738320cb264c79c9b0fcf7c6898`

- The Windows PLAN-003 pull-request run
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29191999872` and the
  PLAN-001 workflow-dispatch run
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29192002449` first failed
  the two-initializer corpus case while its public error code was still hidden.
- Aligning that corpus fixture with the existing 5,000 ms correctness budget exposed
  the exact remaining failure in Windows PLAN-003 run
  `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29192411636`:
  the direct eight-initializer test returned `STORE_BUSY`.
- The process-local setup gate serialized all SQLite setup, but still capped itself at
  1,000 one-millisecond polls even when the checked configuration allowed 5,000 ms.
  The failed 3.86-second test binary was too short for the later 5,000 ms root/SQLite
  budgets to be the exhausted boundary. The earlier fixture-only remediation was
  therefore incomplete under hosted Windows scheduler pressure.

The bounded correction raises only that process-local polling cap to 5,000 attempts.
Every poll still checks the injected boot-monotonic deadline; the configured busy bound,
SQLite busy timeout, root lease, claim deadlines and the separate SC-004 latency oracle
remain unchanged. Both concurrent initializers must still succeed, verify the exact
schema and reopen one healthy empty store. The corpus now preserves the payload-free
public error code if a later failure recurs. Cross-host confirmation remains pending in
T069; none of the failed runs above is represented as new immutable success evidence.
