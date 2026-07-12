---
type: "benchmark"
date: "2026-07-12T01:57:23.746170+00:00"
question: "What did the first clean PLAN-004 physical M4 benchmark attempt reveal?"
contributor: "graphify"
outcome: "dead_end"
source_nodes: ["SqliteCoordinatorStoreV1", "verify_full", "ControlledBenchmarkCaseV1"]
---

# Q: What did the first clean PLAN-004 physical M4 benchmark attempt reveal?

## Answer

At source commit 32c6e27d3377df96357452ff5631262d15860888, the clean controlled run committed 239 operations and published no artifacts before a bounded preparation refusal. The last final capability sample was 199728 ms old against a 200000 ms synthetic maximum. The ordinary path also performed four full historical store verifications per operation, producing quadratic work inconsistent with the Phase D lightweight-invariant contract and the latency gate. Do not retry this source unchanged; retain full verification for open, uncertain readback and maintenance, and use an externally-change-detecting incremental proof plus targeted eight-member postconditions for normal preparation.

## Outcome

- Signal: dead_end

## Source Nodes

- SqliteCoordinatorStoreV1
- verify_full
- ControlledBenchmarkCaseV1