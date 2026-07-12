---
type: "implementation"
date: "2026-07-11T08:51:40.542335+00:00"
question: "What RED interfaces do PLAN-004 T042/T043 contention and deadline tests require?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["contention.rs", "deadline.rs", "SyntheticPreparationCaseV1"]
---

# Q: What RED interfaces do PLAN-004 T042/T043 contention and deadline tests require?

## Answer

T042/T043 tests now exist. RED evidence from cargo test --no-run: prepare.rs lacks commit_synthetic_preparation_until_v1; contention additionally lacks provision_synthetic_budget_scope_with_total_v1 and SyntheticPreparationCaseV1::distinct_operation_in_shared_scope_v1. The process probe self-spawns the integration-test executable, so no extra helper binary is required. Release gates are ignored at 100x64 threads, 20x8 processes, and 1000 held-writer attempts with >=250ms post-return observation.

## Outcome

- Signal: useful

## Source Nodes

- contention.rs
- deadline.rs
- SyntheticPreparationCaseV1