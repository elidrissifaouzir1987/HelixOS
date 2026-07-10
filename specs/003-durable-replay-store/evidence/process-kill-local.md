# PLAN-003 local process-kill evidence

**Recorded**: 2026-07-10
**Host**: Microsoft Windows 10.0.26200, x64
**Toolchain**: rustc/cargo 1.96.1, `x86_64-pc-windows-msvc`
**Git base**: `6b31af88af28f4356517846acb9f3bb77a48fcf6`
**Status**: passing local working-tree process-kill evidence; explicitly not power-loss evidence

Final command:

```text
cargo test --locked --release -p helix-replay-sqlite --features test-fault-injection --test process_crash -- --ignored --test-threads=1
```

Result:

```text
test result: ok. 6 passed; 0 failed
finished in 0.94s
```

The six parent matrices killed and reaped children at 18 frozen boundaries:

- initialization: schema staged, initialization committed;
- claim: opened, writer acquired, generation updated, row inserted, before commit,
  commit returned, before result acknowledgement;
- backup: database complete, manifest staged, package published;
- checkpoint: before mutation, SQLite call returned;
- restore: destination reserved, database staged, database published, WAL/FULL profile
  reverified.

Fresh processes then proved all-or-none claim state, full integrity, restartable
initialization/checkpoint state, manifest-last backup rejection/publication, and durable
`RESTORE_PENDING` nonactivation with no destination clobber. Fault hooks and environment
selectors compile only with the non-default `test-fault-injection` feature.

`Child::kill` evidence covers application/process termination. It does **not** cover
power removal, torn sectors, controller caches, directory-entry persistence,
`F_FULLFSYNC`, or the actual Mac mini M4 filesystem.
