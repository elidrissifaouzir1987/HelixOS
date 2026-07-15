---
type: "benchmark"
date: "2026-07-14T16:27:37.522516+00:00"
question: "PLAN-005 T095 second exact physical M4 remediation benchmark result"
contributor: "graphify"
outcome: "useful"
source_nodes: ["durable_dispatch_benchmark.rs", "dispatch_receipt.rs", "connection.rs"]
---

# Q: PLAN-005 T095 second exact physical M4 remediation benchmark result

## Answer

A distinct create-only second benchmark completed exit 0 in 2095.23 seconds. Independent validation found 10000 exact samples and phase partitions, 10500 committed EXECUTING receipts, WAL/FULL on fresh independent stores, and no privacy markers. p50=46.978208ms, p95=50.993542ms, p99=55.019375ms, max=87.097416ms. p95 still misses the 50ms limit by 0.993542ms while p99 passes; PERF-002 remains pending. Evidence SHA-256 is 0382871d78260bd321d0a6f7d707a2da556e9addeef80af0abd33b10676c7454. The artifact must be retained and not selected away.

## Outcome

- Signal: useful

## Source Nodes

- durable_dispatch_benchmark.rs
- dispatch_receipt.rs
- connection.rs