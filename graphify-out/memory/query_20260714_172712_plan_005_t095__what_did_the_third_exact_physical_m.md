---
type: "benchmark"
date: "2026-07-14T17:27:12.715199+00:00"
question: "PLAN-005 T095: what did the third exact physical M4 remediation run establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["handoff_exact_grant_once_inner_v1", "commit_execution_receipt_v1"]
---

# Q: PLAN-005 T095: what did the third exact physical M4 remediation run establish?

## Answer

The create-only artifact specs/005-durable-dispatch/evidence/m4-remediation-3-raw.json completed successfully in 1928.00s with SHA-256 07daefe5621f8843690108f51188151a04052c5a53e168192b76399eba742104 and 2,976,408 bytes. Independent validation found zero errors across 10,000 exact phase partitions and 10,500 committed EXECUTING receipts under independent WAL/FULL stores. Nearest-rank totals were p50 44.310000ms, p95 50.030833ms, p99 52.182792ms, max 80.315959ms. SC-005 still misses p95 by 30.833us while p99 passes by 47.817208ms. The artifact must be retained, no selective rerun is allowed, PERF-002 remains pending, and the next change requires a meaningful production optimization.

## Outcome

- Signal: useful

## Source Nodes

- handoff_exact_grant_once_inner_v1
- commit_execution_receipt_v1