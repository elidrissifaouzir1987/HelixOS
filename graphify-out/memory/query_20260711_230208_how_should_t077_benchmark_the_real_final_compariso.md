---
type: "query"
date: "2026-07-11T23:02:08.655552+00:00"
question: "How should T077 benchmark the real final-comparison and production durable commit path while preserving the dependency and authority boundaries?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["prepare_plan_v1()", "SqliteCoordinatorStoreV1", "commit_preparing_transaction_v1()", "durable_preparation_benchmark.rs", "controlled_benchmark.rs"]
---

# Q: How should T077 benchmark the real final-comparison and production durable commit path while preserving the dependency and authority boundaries?

## Answer

Expanded from graph vocabulary: [benchmark, commit, comparison, coordinator, durable, final, prepare, production, reopen, signed, sqlite, store]. T077 now prebuilds unique authenticated Ed25519 L2 irreversible plans and eligibility plus trusted synthetic budget scopes outside the timer, then measures the real prepare_plan_v1 orchestration through SqliteCoordinatorStoreV1::commit_preparing and commit_preparing_transaction_v1. A non-default controlled-benchmark feature exposes only a doc-hidden facade; coordinator keeps no direct helix-plan-eligibility dependency and test-fault-injection is not reused. Each sample receives an exclusive absolute monotonic deadline, asserts zero recovery-provider calls, and the run closes then fully reopens SqliteCoordinatorStoreV1 with retained root identity and historical signing-key resolver before raw evidence projection. Release execution refuses dirty source before creating roots or outputs.

## Outcome

- Signal: useful

## Source Nodes

- prepare_plan_v1()
- SqliteCoordinatorStoreV1
- commit_preparing_transaction_v1()
- durable_preparation_benchmark.rs
- controlled_benchmark.rs