---
type: "query"
date: "2026-07-12T10:20:44.204583+00:00"
question: "Diagnose PLAN-001 macOS held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later deadline failure"
contributor: "graphify"
outcome: "useful"
source_nodes: ["deadline.rs", "run_held_writer_attempt_v1()", "commit_synthetic_preparation_until_v1()", "configure_deadline_bounded_busy_timeout_v1()"]
---

# Q: Diagnose PLAN-001 macOS held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later deadline failure

## Answer

Expanded from original query via graph vocab: [deadline, writer, clock, busy, timeout, held, coordinator, synthetic, monotonic, contention, elapsed]. Four macOS hosted runs at the same source behavior exceeded the strict 40 ms plus 50 ms wall-clock bound (138, 170, 183, and 278 ms) only while the deadline integration binary ran 53 tests at default parallelism. Linux passed, the physical M4 controlled release gate passed 1,000 attempts, and the exact all-feature test passes repeatedly when isolated/serialized. The implementation configures SQLite busy_timeout from the injected live remaining absolute deadline and does no detached retry. This is a CI harness scheduling flaw, not evidence of a mutation/deadline implementation defect. Preserve the 50 ms assertion and serialize contracts.yml workspace tests with libtest --test-threads=1, matching durable-preparation.yml; then rerun the full matrix.

## Outcome

- Signal: useful

## Source Nodes

- deadline.rs
- run_held_writer_attempt_v1()
- commit_synthetic_preparation_until_v1()
- configure_deadline_bounded_busy_timeout_v1()