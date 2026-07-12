---
type: "implementation"
date: "2026-07-11T11:18:45.612669+00:00"
question: "What is the PLAN-004 T052 retention-test boundary?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["retention.rs", "quarantine.rs", "failure.rs"]
---

# Q: What is the PLAN-004 T052 retention-test boundary?

## Answer

The new coordinator retention integration test covers the absence of v1 pruning surfaces, permanent FAILED and RELEASED history, whole-graph prune refusal, permanent quarantine evidence, and true-orphan reverse/OR REPLACE rejection. Its intentional RED boundary is limited to the missing crate-private retain_synthetic_orphan_v1 and SyntheticOrphanInputV1 interfaces.

## Outcome

- Signal: useful

## Source Nodes

- retention.rs
- quarantine.rs
- failure.rs