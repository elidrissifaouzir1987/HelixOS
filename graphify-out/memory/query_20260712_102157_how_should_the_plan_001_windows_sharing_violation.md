---
type: "ci-failure"
date: "2026-07-12T10:21:57.187468+00:00"
question: "How should the PLAN-001 Windows sharing-violation test failures in connection.rs and maintenance.rs be corrected without changing production semantics?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat OS sharing violations as test handle-lifetime issues: retain the custody handle that carries the invariant, close unrelated SQLite handles before Windows unlink or cleanup, and preserve the same fail-closed assertions."
source_nodes: ["connection.rs", "maintenance.rs", "ReservedDatabaseFileV1", "ProvisionedBackupDestinationV1"]
---

# Q: How should the PLAN-001 Windows sharing-violation test failures in connection.rs and maintenance.rs be corrected without changing production semantics?

## Answer

The failures were test-owned handle-lifetime assumptions. In the file-identity test, close only the SQLite connection on Windows before the unlink while retaining the original reservation handle, then replace with byte-identical content and require fingerprint refusal. In the publication-cleanup test, drop the destination and its otherwise-unused SQLite connection before recursive fixture deletion. The two focused tests, all 111 coordinator library tests, rustfmt, and strict Clippy pass on macOS; Windows cross-check reaches libsqlite3-sys but is blocked locally by the absent MSVC C SDK.

## Outcome

- Signal: corrected
- Correction: Treat OS sharing violations as test handle-lifetime issues: retain the custody handle that carries the invariant, close unrelated SQLite handles before Windows unlink or cleanup, and preserve the same fail-closed assertions.

## Source Nodes

- connection.rs
- maintenance.rs
- ReservedDatabaseFileV1
- ProvisionedBackupDestinationV1