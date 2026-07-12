---
type: "implementation"
date: "2026-07-11T09:04:58.110699+00:00"
question: "What implementation made PLAN-004 T042/T043 normal contention and held-writer tests pass?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["commit_synthetic_preparation_until_v1", "SyntheticPreparationCaseV1", "contention.rs", "deadline.rs"]
---

# Q: What implementation made PLAN-004 T042/T043 normal contention and held-writer tests pass?

## Answer

The cfg-test SQLite seam now creates coherent signed distinct operations over one exact shared scope, provisions an explicit four-dimensional total create-only, allocates transaction generations from the serialized metadata snapshot, distinguishes exact capacity exhaustion from binding conflict, and uses one native busy_timeout bounded by an injected absolute monotonic deadline with equality checks after writer acquisition and before COMMIT. T042 passed 12 normal tests with 4 release tests ignored; T043 passed 12 normal tests with 1 release test ignored.

## Outcome

- Signal: useful

## Source Nodes

- commit_synthetic_preparation_until_v1
- SyntheticPreparationCaseV1
- contention.rs
- deadline.rs