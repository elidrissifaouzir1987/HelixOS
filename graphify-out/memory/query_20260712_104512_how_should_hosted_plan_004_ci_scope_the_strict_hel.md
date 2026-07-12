---
type: "query"
date: "2026-07-12T10:45:12.325111+00:00"
question: "How should hosted PLAN-004 CI scope the strict held-writer wall-clock oracle without weakening SC-010?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later", "deadline.rs", "durable-preparation.yml"]
---

# Q: How should hosted PLAN-004 CI scope the strict held-writer wall-clock oracle without weakening SC-010?

## Answer

The hosted PLAN-004 matrix keeps helix-coordinator-sqlite all-targets/all-features tests serial and exact-skips only held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later. The descriptor and summary identify PLAN-004-T043-SC-010-controlled-target as owner and set physical_performance_evidence=false. The oracle still compiles and lints; its unchanged 1,000-iteration release gate remains controlled physical Mac mini M4 evidence rather than a noisy hosted-runner portability check.

## Outcome

- Signal: useful

## Source Nodes

- held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later
- deadline.rs
- durable-preparation.yml