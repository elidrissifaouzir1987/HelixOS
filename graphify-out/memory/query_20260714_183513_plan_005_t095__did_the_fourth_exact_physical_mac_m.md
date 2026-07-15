---
type: "benchmark"
date: "2026-07-14T18:35:13.160032+00:00"
question: "PLAN-005 T095: did the fourth exact physical Mac mini M4 remediation satisfy SC-005?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["receive_grant_v1", "commit_dispatch_transaction_v1", "commit_execution_receipt_v1"]
---

# Q: PLAN-005 T095: did the fourth exact physical Mac mini M4 remediation satisfy SC-005?

## Answer

Yes. The create-only artifact specs/005-durable-dispatch/evidence/m4-remediation-4-raw.json completed in 2031.76s with SHA-256 c37c2d3dde82bcb7da86b0400e4abccf64a0358a4a056f0aad8a8e9396af343f and 2,976,416 bytes. Independent validation found zero errors across 10,000 exact four-phase partitions and 10,500 committed EXECUTING receipts under independent WAL/FULL stores. Nearest-rank results were p50 45.431542ms, p95 49.416541ms, p99 51.917875ms and max 76.199000ms. P95 passes the 50ms limit by 0.583459ms and p99 passes 100ms by 48.082125ms. All earlier failed artifacts remain unchanged; no selective rerun occurred. This passes the controlled physical local-working-tree percentile portion of PERF-002, but not immutable exact-commit, power-loss, fullfsync, approved at-rest, production-provider, isolation or Tier 1 claims.

## Outcome

- Signal: useful

## Source Nodes

- receive_grant_v1
- commit_dispatch_transaction_v1
- commit_execution_receipt_v1