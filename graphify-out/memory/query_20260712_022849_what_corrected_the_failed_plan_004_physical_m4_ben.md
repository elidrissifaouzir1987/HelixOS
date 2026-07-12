---
type: "benchmark"
date: "2026-07-12T02:28:49.725249+00:00"
question: "What corrected the failed PLAN-004 physical M4 benchmark and what did the retained run prove?"
contributor: "graphify"
outcome: "corrected"
correction: "Use f7b021db52503aaedcc59b9c9c8d95d357555352 and its retained artifacts for the corrected local result; keep the earlier 32c6e27 attempt only as a dead-end diagnostic."
source_nodes: ["SqliteCoordinatorStoreV1", "VerifiedStoreObserverV1", "ControlledBenchmarkCaseV1", "verify_active_operation_snapshot_v1"]
---

# Q: What corrected the failed PLAN-004 physical M4 benchmark and what did the retained run prove?

## Answer

At clean source commit f7b021db52503aaedcc59b9c9c8d95d357555352, the controlled physical Mac mini M4 run completed 500 warmups and 10000 measured operations with 10500 acknowledged commits. It recorded p50 11218708 ns, p95 24096375 ns, p99 25443666 ns and max 26528459 ns, so both local latency thresholds passed. Coordinator artifact SHA-256 is ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12 and the separate recovery-transfer artifact SHA-256 is da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e. The correction replaced four per-operation historical scans with a persistent SQLite data_version observer, a bounded ACTIVE snapshot proof and an exact staged eight-member postcondition, while retaining full verification for open, reopen, external commits, uncertain readback and maintenance. This is retained local evidence only; immutable CI, supply-chain, at-rest approval, power-loss and Tier 1 gates remain pending.

## Outcome

- Signal: corrected
- Correction: Use f7b021db52503aaedcc59b9c9c8d95d357555352 and its retained artifacts for the corrected local result; keep the earlier 32c6e27 attempt only as a dead-end diagnostic.

## Source Nodes

- SqliteCoordinatorStoreV1
- VerifiedStoreObserverV1
- ControlledBenchmarkCaseV1
- verify_active_operation_snapshot_v1