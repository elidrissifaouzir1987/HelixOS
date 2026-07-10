# PLAN-003 local contention evidence

**Recorded**: 2026-07-10
**Host**: Microsoft Windows 10.0.26200, x64
**Toolchain**: rustc/cargo 1.96.1, `x86_64-pc-windows-msvc`
**Git base**: `6b31af88af28f4356517846acb9f3bb77a48fcf6`
**Status**: passing local working-tree evidence; not immutable CI or Mac mini M4 evidence

Final command:

```text
cargo test --locked --release -p helix-replay-sqlite --test contention release_thread_then_process_contention_suite -- --ignored --nocapture --test-threads=1
```

Result:

```text
PLAN-003 thread contention scenarios=4 rounds_per_scenario=100 contenders=64 status=pass
PLAN-003 process contention rounds=20 contenders=8 winners_per_round=1 status=pass
test result: ok. 1 passed; 0 failed
finished in 70.42s
```

The thread gate executed exact-repeat, nonce-conflict, operation-conflict and independent
binding scenarios: 25,600 synchronized thread contenders in total. The process gate
executed 20 shell-free `READY`/`GO` rounds with 8 processes each: 160 contenders, exactly
one durable winner per round. Every round reopened and verified generation, row count
and both unique indexes. No native path, nonce, operation identifier or digest was
printed.

This proves controlled process/thread contention on this Windows host only. It does not
prove hosted three-platform reproducibility, target M4 latency, filesystem power-loss
behavior, `F_FULLFSYNC`, or safe operation on network/cloud/removable filesystems.
